package card

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/transport"
)

func TestCanceledEncipherDoesNotTransmit(t *testing.T) {
	want := append([]byte{0x02}, make([]byte, 16)...)

	var calls, closes int

	d := New(&exchangeTransport{
		exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
			calls++
			return success(want), nil
		},
		close: func() error { closes++; return nil },
	})

	t.Cleanup(func() { _ = d.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	got, err := d.Encipher(ctx, make([]byte, 16), nil)
	if !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("Encipher = %x, %v; want no ciphertext and context.Canceled", got, err)
	}

	if calls != 0 || closes != 0 {
		t.Errorf("calls = %d, closes = %d; want no I/O or close", calls, closes)
	}

	got, err = d.Encipher(t.Context(), make([]byte, 16), nil)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Encipher after cancellation = %x, %v; want %x", got, err, want)
	}

	if calls != 1 || closes != 0 {
		t.Errorf("calls = %d, closes = %d; want 1, 0", calls, closes)
	}
}

func TestInvalidatedEncipherClosesDevice(t *testing.T) {
	cause := errors.New("connection lost")
	closeErr := errors.New("disconnect failed")

	var calls, closes int

	d := New(&exchangeTransport{
		exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
			calls++
			return iso7816.Response{}, &transport.DeviceInvalidatedError{Err: cause}
		},
		close: func() error { closes++; return closeErr },
	})

	t.Cleanup(func() { _ = d.Close() })

	got, err := d.Encipher(t.Context(), make([]byte, 16), nil)

	var invalidated *transport.DeviceInvalidatedError
	if got != nil || !errors.As(err, &invalidated) || !errors.Is(err, cause) || !errors.Is(err, closeErr) {
		t.Fatalf("Encipher = %x, %v; want no ciphertext, invalidation, I/O cause, and close cause", got, err)
	}

	if _, err := d.Encipher(t.Context(), make([]byte, 16), nil); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("next Encipher error = %v, want closed pipe", err)
	}

	if err := d.Close(); !errors.Is(err, closeErr) {
		t.Errorf("Close error = %v, want disconnect failure", err)
	}

	if calls != 1 || closes != 1 {
		t.Errorf("calls = %d, closes = %d; want 1, 1", calls, closes)
	}
}
