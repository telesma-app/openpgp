package card

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/telesma-app/iso7816"
)

func TestComputeDigitalSignature(t *testing.T) {
	for _, authenticate := range []bool{false, true} {
		mode := "current verification"
		if authenticate {
			mode = "PW1Sign verification"
		}

		for _, test := range []struct {
			name     string
			response iso7816.Response
			cause    error
		}{
			{name: "success", response: success([]byte{0xa1, 0xb2, 0xc3})},
			{name: "APDU rejection", response: iso7816.Response{Status: 0x6982}},
			{name: "transport failure", cause: io.ErrUnexpectedEOF},
		} {
			t.Run(mode+"/"+test.name, func(t *testing.T) {
				input := []byte{1, 2, 3}
				password := []byte("123456")

				want := [][]byte{{0, 0x2a, 0x9e, 0x9a, 3, 1, 2, 3, 0}}
				if authenticate {
					want = append([][]byte{{0, 0x20, 0, 0x81, 6, '1', '2', '3', '4', '5', '6'}}, want...)
				}

				var calls, sourceCalls, closes int

				d := New(&exchangeTransport{
					exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
						if calls >= len(want) {
							t.Fatalf("unexpected command INS=%02x after %d exchanges", command.INS, calls)
						}

						raw, err := command.MarshalBinary()
						if err != nil {
							t.Fatal(err)
						}

						if !bytes.Equal(raw, want[calls]) {
							t.Errorf("command %d = %x, want %x", calls, raw, want[calls])
						}

						calls++

						if command.INS == 0x20 {
							return success(nil), nil
						}

						if authenticate && !bytes.Equal(password, make([]byte, len(password))) {
							t.Error("transferred password was not cleared before signing")
						}

						return test.response, test.cause
					},
					close: func() error { closes++; return nil },
				})

				t.Cleanup(func() { _ = d.Close() })

				var source AuthenticationSource
				if authenticate {
					source = func(context.Context) ([]byte, error) {
						sourceCalls++
						return password, nil
					}
				}

				got, err := d.ComputeDigitalSignature(t.Context(), input, source)

				switch {
				case test.cause != nil:
					if !errors.Is(err, test.cause) || got != nil {
						t.Errorf("signature = %x, %v; want nil and %v", got, err, test.cause)
					}
				case test.response.Status != 0x9000:
					var apdu *iso7816.APDUError
					if !errors.As(err, &apdu) || apdu.StatusWord() != test.response.Status || got != nil {
						t.Errorf("signature = %x, %v; want nil and APDU error %s", got, err, test.response.Status)
					}
				default:
					if err != nil || !bytes.Equal(got, []byte{0xa1, 0xb2, 0xc3}) {
						t.Errorf("signature = %x, %v; want a1b2c3 and nil", got, err)
					}
				}

				wantSources := 0
				if authenticate {
					wantSources = 1
				}

				if calls != len(want) || sourceCalls != wantSources || closes != 0 {
					t.Errorf("exchanges=%d sources=%d closes=%d; want %d, %d, 0", calls, sourceCalls, closes, len(want), wantSources)
				}

				if !bytes.Equal(input, []byte{1, 2, 3}) {
					t.Error("signing changed the borrowed input")
				}
			})
		}
	}
}
