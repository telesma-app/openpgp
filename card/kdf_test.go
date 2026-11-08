package card

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport"
)

func TestKDFOperations(t *testing.T) {
	var commands [][]byte

	d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
		raw, err := command.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}

		commands = append(commands, raw)

		if command.INS == 0xca {
			return success([]byte{0x81, 1, 0}), nil
		}

		return success(nil), nil
	}})

	t.Cleanup(func() { _ = d.Close() })

	kdf, err := d.GetKDF(t.Context())
	if err != nil || kdf.Algorithm != protocol.KDFNone {
		t.Fatalf("KDF = %+v, %v", kdf, err)
	}

	if err := d.PutKDF(t.Context(), kdf, nil); err != nil {
		t.Fatal(err)
	}

	if len(commands) != 2 || !bytes.Equal(commands[0], []byte{0, 0xca, 0, 0xf9, 0}) ||
		!bytes.Equal(commands[1], []byte{0, 0xda, 0, 0xf9, 3, 0x81, 1, 0}) {
		t.Errorf("commands = %x, want GET KDF and PUT KDF only", commands)
	}
}

func TestInvalidatedKDFOperationClosesDevice(t *testing.T) {
	for _, test := range []struct {
		name string
		call func(context.Context, *Device) error
	}{
		{
			name: "read",
			call: func(ctx context.Context, d *Device) error {
				_, err := d.GetKDF(ctx)
				return err
			},
		},
		{
			name: "write",
			call: func(ctx context.Context, d *Device) error {
				return d.PutKDF(ctx, protocol.KDF{Algorithm: protocol.KDFNone}, nil)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cause := io.ErrUnexpectedEOF

			var calls, closes int

			d := New(&exchangeTransport{
				exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
					calls++
					return iso7816.Response{}, &transport.DeviceInvalidatedError{Err: cause}
				},
				close: func() error { closes++; return nil },
			})

			t.Cleanup(func() { _ = d.Close() })

			err := test.call(t.Context(), d)

			var invalidated *transport.DeviceInvalidatedError
			if !errors.As(err, &invalidated) || !errors.Is(err, cause) || closes != 1 {
				t.Fatalf("error = %v, closes = %d; want invalidation and one close", err, closes)
			}

			if err := test.call(t.Context(), d); !errors.Is(err, io.ErrClosedPipe) || calls != 1 {
				t.Errorf("next error = %v, calls = %d; want closed without another exchange", err, calls)
			}
		})
	}
}
