package card

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"testing/synctest"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport"
)

func TestPutPWStatusBytesAuthentication(t *testing.T) {
	cause := errors.New("password source failed")

	verify := []byte{0, 0x20, 0, 0x83, 8, 0x28, 0x12, 0x34, 0x56, 0x78, 0xff, 0xff, 0xff}
	for _, form := range []struct {
		name   string
		update protocol.PWStatusBytesUpdate
		wire   []byte
	}{
		{
			name:   "signing policy",
			update: protocol.PWStatusBytesUpdate{PW1ValidForMultipleSignatures: true},
			wire:   []byte{0, 0xda, 0, 0xc4, 1, 1},
		},
		{
			name: "length and format",
			update: protocol.PWStatusBytesUpdate{
				PW1ValidForMultipleSignatures: true,
				LengthAndFormat: &protocol.PWLengthAndFormat{
					PW1MaxLength: 32, ResettingCodeMaxLength: 32, PW3MaxLength: 64,
					PW1PINBlock2: true,
				},
			},
			wire: []byte{0, 0xda, 0, 0xc4, 4, 1, 0xa0, 0x20, 0x40},
		},
	} {
		for _, test := range []struct {
			name         string
			authenticate bool
			sourceError  error
			verifyStatus iso7816.StatusWord
			commands     [][]byte
		}{
			{name: "current verification", commands: [][]byte{form.wire}},
			{name: "source error", authenticate: true, sourceError: cause},
			{name: "wrong PW3", authenticate: true, verifyStatus: 0x63c2, commands: [][]byte{verify}},
			{name: "PW3 and write", authenticate: true, verifyStatus: 0x9000, commands: [][]byte{verify, form.wire}},
		} {
			t.Run(form.name+"/"+test.name, func(t *testing.T) {
				var calls, sourceCalls int

				password := []byte{0x28, 0x12, 0x34, 0x56, 0x78, 0xff, 0xff, 0xff}
				d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
					raw, err := command.MarshalBinary()
					if err != nil {
						t.Fatal(err)
					}

					if calls >= len(test.commands) {
						t.Fatalf("unexpected command = %x", raw)
					}

					if !bytes.Equal(raw, test.commands[calls]) {
						t.Errorf("command = %x, want %x", raw, test.commands[calls])
					}

					calls++

					if command.INS == byte(protocol.Verify) {
						return iso7816.Response{Status: test.verifyStatus}, nil
					}

					return success(nil), nil
				}})

				t.Cleanup(func() { _ = d.Close() })

				var authentication AuthenticationSource
				if test.authenticate {
					authentication = func(context.Context) ([]byte, error) {
						sourceCalls++

						return password, test.sourceError
					}
				}

				var before protocol.PWLengthAndFormat
				if form.update.LengthAndFormat != nil {
					before = *form.update.LengthAndFormat
				}

				err := d.PutPWStatusBytes(t.Context(), form.update, authentication)

				if test.sourceError != nil {
					if !errors.Is(err, test.sourceError) {
						t.Errorf("error = %v, want %v", err, test.sourceError)
					}
				} else if test.verifyStatus == 0x63c2 {
					var apdu *iso7816.APDUError
					if !errors.As(err, &apdu) || apdu.StatusWord() != 0x63c2 {
						t.Errorf("error = %v, want PW3 rejection 63C2", err)
					}
				} else if err != nil {
					t.Error(err)
				}

				if calls != len(test.commands) || (test.authenticate && sourceCalls != 1) || (!test.authenticate && sourceCalls != 0) {
					t.Errorf("exchanges=%d source calls=%d; want %d exchanges", calls, sourceCalls, len(test.commands))
				}

				if form.update.LengthAndFormat != nil && *form.update.LengthAndFormat != before {
					t.Error("writing status bytes changed the borrowed length-and-format group")
				}

				if test.authenticate && test.sourceError == nil {
					if !bytes.Equal(password, make([]byte, len(password))) {
						t.Error("transferred PW3 was not cleared")
					}
				} else if !bytes.Equal(password, []byte{0x28, 0x12, 0x34, 0x56, 0x78, 0xff, 0xff, 0xff}) {
					t.Error("PW3 changed without an ownership transfer")
				}
			})
		}
	}
}

func TestPutPWStatusBytesKeepsVerificationAndWriteTogether(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		verifyStarted := make(chan struct{})
		continueVerify := make(chan struct{})

		defer func() {
			select {
			case <-continueVerify:
			default:
				close(continueVerify)
			}
		}()

		var sequence []byte

		d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
			sequence = append(sequence, command.INS)
			if command.INS == byte(protocol.Verify) {
				if command.P2 != byte(protocol.PW3) {
					t.Errorf("verification reference = %02x, want PW3", command.P2)
				}

				close(verifyStarted)
				<-continueVerify
			}

			return success(nil), nil
		}})

		t.Cleanup(func() { _ = d.Close() })

		written := make(chan error, 1)
		go func() {
			written <- d.PutPWStatusBytes(t.Context(), protocol.PWStatusBytesUpdate{}, func(context.Context) ([]byte, error) {
				return []byte("12345678"), nil
			})
		}()

		receive(t, verifyStarted, "PW3 verification starting")

		read := make(chan error, 1)

		go func() {
			_, err := d.GetData(t.Context(), protocol.URLObject)
			read <- err
		}()

		synctest.Wait()

		if !bytes.Equal(sequence, []byte{0x20}) {
			t.Fatalf("command interleaved during PW3 verification: %x", sequence)
		}

		close(continueVerify)

		if err := receive(t, written, "PW status write completion"); err != nil {
			t.Fatal(err)
		}

		if err := receive(t, read, "queued read completion"); err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(sequence, []byte{0x20, 0xda, 0xca}) {
			t.Errorf("sequence = %x, want VERIFY, PUT DATA, GET DATA", sequence)
		}
	})
}

func TestInvalidatedPWStatusBytesWriteClosesDevice(t *testing.T) {
	var calls, closes int

	d := New(&exchangeTransport{
		exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
			calls++

			return iso7816.Response{}, &transport.DeviceInvalidatedError{Err: io.ErrUnexpectedEOF}
		},
		close: func() error { closes++; return nil },
	})

	t.Cleanup(func() { _ = d.Close() })

	err := d.PutPWStatusBytes(t.Context(), protocol.PWStatusBytesUpdate{}, nil)

	var invalidated *transport.DeviceInvalidatedError
	if !errors.As(err, &invalidated) || !errors.Is(err, io.ErrUnexpectedEOF) || closes != 1 {
		t.Fatalf("error = %v, closes=%d; want invalidation and one close", err, closes)
	}

	if err := d.PutPWStatusBytes(t.Context(), protocol.PWStatusBytesUpdate{}, nil); !errors.Is(err, io.ErrClosedPipe) || calls != 1 {
		t.Errorf("write after invalidation = %v, exchanges=%d", err, calls)
	}
}
