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

func TestBulkCertificatesKeepCursorUntilReadCompletes(t *testing.T) {
	for _, test := range []struct {
		name  string
		write bool
	}{
		{name: "queued read"},
		{name: "queued write", write: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				nextStarted := make(chan struct{})
				continueNext := make(chan struct{})

				defer func() {
					select {
					case <-continueNext:
					default:
						close(continueNext)
					}
				}()

				certificates := map[byte][]byte{
					0: {0x30, 0x01, 0xa0},
					1: {0x30, 0x01, 0xd0},
					2: {0x30, 0x01, 0xb0},
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
					case byte(protocol.GetNextData):
						selected++

						if len(commands) == 3 {
							close(nextStarted)
							<-continueNext
						}

						return success(certificates[selected]), nil
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

				type bulkResult struct {
					certificates protocol.CardholderCertificates
					err          error
				}

				bulk := make(chan bulkResult, 1)

				go func() {
					certificates, err := d.GetCardholderCertificates(t.Context())
					bulk <- bulkResult{certificates: certificates, err: err}
				}()

				receive(t, nextStarted, "bulk decryption certificate read")

				queued := make(chan error, 1)

				go func() {
					if test.write {
						queued <- d.PutCardholderCertificate(t.Context(), protocol.AuthenticationTemplateTag, []byte{0x30, 0x01, 0xff}, nil)
						return
					}

					got, err := d.GetCardholderCertificate(t.Context(), protocol.AuthenticationTemplateTag)
					if err == nil && !bytes.Equal(got, []byte{0x30, 0x01, 0xa0}) {
						t.Errorf("queued AUT certificate = %x, want 3001a0", got)
					}

					queued <- err
				}()

				synctest.Wait()

				if len(commands) != 3 {
					t.Fatalf("commands during bulk GET NEXT DATA = %x, want SELECT, GET, NEXT", commands)
				}

				close(continueNext)

				result := receive(t, bulk, "bulk certificate read completion")
				if result.err != nil {
					t.Fatal(result.err)
				}

				if err := receive(t, queued, "queued certificate operation"); err != nil {
					t.Fatal(err)
				}

				if !bytes.Equal(result.certificates.Authentication, []byte{0x30, 0x01, 0xa0}) ||
					!bytes.Equal(result.certificates.Decryption, []byte{0x30, 0x01, 0xd0}) ||
					!bytes.Equal(result.certificates.Signature, []byte{0x30, 0x01, 0xb0}) {
					t.Errorf("bulk certificates = %+v, want AUT 3001a0, DEC 3001d0, SIG 3001b0", result.certificates)
				}

				want := [][]byte{
					{0x00, 0xa5, 0x00, 0x04, 0x06, 0x60, 0x04, 0x5c, 0x02, 0x7f, 0x21, 0x00},
					{0x00, 0xca, 0x7f, 0x21, 0x00},
					{0x00, 0xcc, 0x7f, 0x21, 0x00},
					{0x00, 0xcc, 0x7f, 0x21, 0x00},
					{0x00, 0xa5, 0x00, 0x04, 0x06, 0x60, 0x04, 0x5c, 0x02, 0x7f, 0x21, 0x00},
					{0x00, 0xca, 0x7f, 0x21, 0x00},
				}
				if test.write {
					want[5] = []byte{0x00, 0xda, 0x7f, 0x21, 0x03, 0x30, 0x01, 0xff}
				}

				if len(commands) != len(want) {
					t.Fatalf("commands = %x, want %x", commands, want)
				}

				for i := range want {
					if !bytes.Equal(commands[i], want[i]) {
						t.Errorf("command %d = %x, want %x", i, commands[i], want[i])
					}
				}
			})
		})
	}
}

func TestInvalidatedNextDataClosesDevice(t *testing.T) {
	for _, test := range []struct {
		name         string
		bulk         bool
		instructions []byte
	}{
		{name: "bulk late GET NEXT DATA", bulk: true, instructions: []byte{0xa5, 0xca, 0xcc, 0xcc}},
		{name: "direct GET NEXT DATA", instructions: []byte{0xcc}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cause := errors.New("connection lost")
			closeErr := errors.New("disconnect failed")

			var calls, closes int

			d := New(&exchangeTransport{
				exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
					calls++
					if calls > len(test.instructions) {
						t.Errorf("unexpected instruction %02x after failure", command.INS)
						return iso7816.Response{}, cause
					}

					if command.INS != test.instructions[calls-1] {
						t.Errorf("instruction %d = %02x, want %02x", calls, command.INS, test.instructions[calls-1])
					}

					if command.INS == byte(protocol.GetNextData) {
						raw, err := command.MarshalBinary()
						if err != nil {
							return iso7816.Response{}, err
						}

						if !bytes.Equal(raw, []byte{0x00, 0xcc, 0x7f, 0x21, 0x00}) {
							t.Errorf("GET NEXT DATA = %x, want 00cc7f2100", raw)
						}
					}

					if calls == len(test.instructions) {
						return iso7816.Response{}, &transport.DeviceInvalidatedError{Err: cause}
					}

					if calls >= 2 {
						return success([]byte{0x30, 0x01, byte(calls)}), nil
					}

					return success(nil), nil
				},
				close: func() error { closes++; return closeErr },
			})

			t.Cleanup(func() { _ = d.Close() })

			var err error

			if test.bulk {
				var got protocol.CardholderCertificates

				got, err = d.GetCardholderCertificates(t.Context())
				if got.Authentication != nil || got.Decryption != nil || got.Signature != nil {
					t.Errorf("bulk result after late failure = %+v, want zero value", got)
				}
			} else {
				var got []byte

				got, err = d.GetNextData(t.Context())
				if got != nil {
					t.Errorf("GET NEXT DATA after failure = %x, want nil", got)
				}
			}

			var invalidated *transport.DeviceInvalidatedError
			if !errors.As(err, &invalidated) || !errors.Is(err, cause) || !errors.Is(err, closeErr) {
				t.Fatalf("error = %v, want invalidation, I/O cause, and close cause", err)
			}

			if _, err := d.GetNextData(t.Context()); !errors.Is(err, io.ErrClosedPipe) {
				t.Errorf("next operation error = %v, want closed pipe", err)
			}

			if err := d.Close(); !errors.Is(err, closeErr) {
				t.Errorf("Close error = %v, want disconnect failure", err)
			}

			if calls != len(test.instructions) || closes != 1 {
				t.Errorf("calls = %d, closes = %d; want %d, 1", calls, closes, len(test.instructions))
			}
		})
	}
}
