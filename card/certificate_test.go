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

func TestCertificateOperationsKeepSelectionAndDataTogether(t *testing.T) {
	for _, test := range []struct {
		name       string
		firstWrite bool
	}{
		{name: "read then write"},
		{name: "write then read", firstWrite: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				selectStarted := make(chan struct{})
				continueSelect := make(chan struct{})

				defer func() {
					select {
					case <-continueSelect:
					default:
						close(continueSelect)
					}
				}()

				certificates := map[byte][]byte{
					1: {0x30, 0x01, 0x11},
					2: {0x30, 0x01, 0x22},
				}

				var (
					selected byte
					commands [][]byte
				)

				d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
					raw, err := command.MarshalBinary()
					if err != nil {
						return iso7816.Response{}, err
					}

					commands = append(commands, raw)

					switch command.INS {
					case byte(protocol.SelectData):
						selected = command.P1

						if len(commands) == 1 {
							close(selectStarted)
							<-continueSelect
						}
					case byte(protocol.GetData):
						return success(certificates[selected]), nil
					case byte(protocol.PutData):
						certificates[selected] = command.Data
					default:
						t.Errorf("unexpected instruction %02x", command.INS)
					}

					return success(nil), nil
				}})

				t.Cleanup(func() { _ = d.Close() })

				first := make(chan error, 1)

				go func() {
					if test.firstWrite {
						first <- d.PutCardholderCertificate(t.Context(), protocol.DigitalSignatureTemplateTag, []byte{0x30, 0x01, 0xa1}, nil)
						return
					}

					got, err := d.GetCardholderCertificate(t.Context(), protocol.DigitalSignatureTemplateTag)
					if err == nil && !bytes.Equal(got, []byte{0x30, 0x01, 0x22}) {
						t.Errorf("SIG certificate = %x, want 300122", got)
					}

					first <- err
				}()

				receive(t, selectStarted, "first certificate selection")

				second := make(chan error, 1)

				go func() {
					if !test.firstWrite {
						second <- d.PutCardholderCertificate(t.Context(), protocol.ConfidentialityTemplateTag, []byte{0x30, 0x01, 0xb2}, nil)
						return
					}

					got, err := d.GetCardholderCertificate(t.Context(), protocol.ConfidentialityTemplateTag)
					if err == nil && !bytes.Equal(got, []byte{0x30, 0x01, 0x11}) {
						t.Errorf("DEC certificate = %x, want 300111", got)
					}

					second <- err
				}()

				synctest.Wait()

				if len(commands) != 1 {
					t.Fatalf("commands during first SELECT = %x, want only SELECT", commands)
				}

				close(continueSelect)

				if err := receive(t, first, "first certificate operation"); err != nil {
					t.Fatal(err)
				}

				if err := receive(t, second, "second certificate operation"); err != nil {
					t.Fatal(err)
				}

				want := [][]byte{
					{0x00, 0xa5, 0x02, 0x04, 0x06, 0x60, 0x04, 0x5c, 0x02, 0x7f, 0x21, 0x00},
					{0x00, 0xca, 0x7f, 0x21, 0x00},
					{0x00, 0xa5, 0x01, 0x04, 0x06, 0x60, 0x04, 0x5c, 0x02, 0x7f, 0x21, 0x00},
					{0x00, 0xda, 0x7f, 0x21, 0x03, 0x30, 0x01, 0xb2},
				}
				if test.firstWrite {
					want[1] = []byte{0x00, 0xda, 0x7f, 0x21, 0x03, 0x30, 0x01, 0xa1}
					want[3] = []byte{0x00, 0xca, 0x7f, 0x21, 0x00}
				}

				if len(commands) != len(want) {
					t.Fatalf("commands = %x, want %x", commands, want)
				}

				for i := range want {
					if !bytes.Equal(commands[i], want[i]) {
						t.Errorf("command %d = %x, want %x", i, commands[i], want[i])
					}
				}

				if test.firstWrite {
					if !bytes.Equal(certificates[2], []byte{0x30, 0x01, 0xa1}) {
						t.Errorf("stored SIG certificate = %x, want 3001a1", certificates[2])
					}
				} else if !bytes.Equal(certificates[1], []byte{0x30, 0x01, 0xb2}) {
					t.Errorf("stored DEC certificate = %x, want 3001b2", certificates[1])
				}
			})
		})
	}
}

func TestCanceledCertificateWaitPreservesDevice(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var (
			commands [][]byte
			closes   int
		)

		d := New(&exchangeTransport{
			exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				raw, err := command.MarshalBinary()
				if err != nil {
					return iso7816.Response{}, err
				}

				commands = append(commands, raw)

				if command.INS == byte(protocol.GetData) {
					return success([]byte{0x30, 0x01, 0x33}), nil
				}

				return success(nil), nil
			},
			close: func() error { closes++; return nil },
		})

		t.Cleanup(func() { _ = d.Close() })

		func() {
			if err := d.lock(t.Context()); err != nil {
				t.Fatal(err)
			}
			defer d.unlock()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			waiting := make(chan error, 1)

			go func() {
				_, err := d.GetCardholderCertificate(ctx, protocol.ConfidentialityTemplateTag)
				waiting <- err
			}()

			synctest.Wait()
			cancel()

			if err := receive(t, waiting, "canceled certificate wait"); !errors.Is(err, context.Canceled) {
				t.Errorf("error = %v, want context.Canceled", err)
			}

			if len(commands) != 0 || closes != 0 {
				t.Errorf("commands = %x, closes = %d; want no I/O or close", commands, closes)
			}
		}()

		got, err := d.GetCardholderCertificate(t.Context(), protocol.AuthenticationTemplateTag)
		if err != nil || !bytes.Equal(got, []byte{0x30, 0x01, 0x33}) {
			t.Fatalf("certificate after cancellation = %x, %v; want 300133", got, err)
		}

		want := [][]byte{
			{0x00, 0xa5, 0x00, 0x04, 0x06, 0x60, 0x04, 0x5c, 0x02, 0x7f, 0x21, 0x00},
			{0x00, 0xca, 0x7f, 0x21, 0x00},
		}
		if len(commands) != len(want) {
			t.Fatalf("commands after cancellation = %x, want %x", commands, want)
		}

		for i := range want {
			if !bytes.Equal(commands[i], want[i]) {
				t.Errorf("command %d = %x, want %x", i, commands[i], want[i])
			}
		}
	})
}

func TestInvalidatedCertificateOperationClosesDevice(t *testing.T) {
	for _, operation := range []struct {
		name  string
		write bool
	}{
		{name: "read"},
		{name: "write", write: true},
	} {
		t.Run(operation.name, func(t *testing.T) {
			for _, phase := range []struct {
				name string
				call int
			}{
				{name: "select", call: 1},
				{name: "data", call: 2},
			} {
				t.Run(phase.name, func(t *testing.T) {
					cause := errors.New("connection lost")
					closeErr := errors.New("disconnect failed")

					var calls, closes int

					d := New(&exchangeTransport{
						exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
							calls++

							wantINS := byte(protocol.SelectData)
							if calls == 2 {
								wantINS = byte(protocol.GetData)
								if operation.write {
									wantINS = byte(protocol.PutData)
								}
							}

							if command.INS != wantINS {
								t.Errorf("instruction = %02x, want %02x", command.INS, wantINS)
							}

							if calls == phase.call {
								return iso7816.Response{}, &transport.DeviceInvalidatedError{Err: cause}
							}

							return success(nil), nil
						},
						close: func() error { closes++; return closeErr },
					})

					t.Cleanup(func() { _ = d.Close() })

					var err error
					if operation.write {
						err = d.PutCardholderCertificate(t.Context(), protocol.DigitalSignatureTemplateTag, []byte{0x30, 0x01, 0x22}, nil)
					} else {
						var got []byte

						got, err = d.GetCardholderCertificate(t.Context(), protocol.DigitalSignatureTemplateTag)
						if got != nil {
							t.Errorf("certificate after invalidation = %x, want nil", got)
						}
					}

					var invalidated *transport.DeviceInvalidatedError
					if !errors.As(err, &invalidated) || !errors.Is(err, cause) || !errors.Is(err, closeErr) {
						t.Fatalf("error = %v, want invalidation, I/O cause, and close cause", err)
					}

					if _, err := d.GetCardholderCertificate(t.Context(), protocol.AuthenticationTemplateTag); !errors.Is(err, io.ErrClosedPipe) {
						t.Errorf("next operation error = %v, want closed pipe", err)
					}

					if err := d.Close(); !errors.Is(err, closeErr) {
						t.Errorf("Close error = %v, want disconnect failure", err)
					}

					if calls != phase.call || closes != 1 {
						t.Errorf("calls = %d, closes = %d; want %d, 1", calls, closes, phase.call)
					}
				})
			}
		})
	}
}
