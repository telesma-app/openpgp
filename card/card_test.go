package card

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport"
)

func TestCloseInterruptsActiveOperationAndReleasesWaiters(t *testing.T) {
	raw := &blockingTransport{started: make(chan struct{}), closed: make(chan struct{})}
	d := New(raw)

	t.Cleanup(func() { _ = d.Close() })

	active := make(chan error, 1)

	go func() {
		_, err := d.GetData(t.Context(), protocol.URLObject)
		active <- err
	}()

	receive(t, raw.started, "active exchange")

	waiting := make(chan error, 1)

	go func() {
		_, err := d.GetData(t.Context(), protocol.URLObject)
		waiting <- err
	}()

	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	if err := receive(t, active, "interrupted operation"); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("active error = %v", err)
	}

	if err := receive(t, waiting, "released waiter"); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("waiting error = %v", err)
	}

	if _, err := d.GetData(t.Context(), protocol.URLObject); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("closed device error = %v", err)
	}
}

func TestCanceledWaitPreservesDevice(t *testing.T) {
	var calls int

	raw := &exchangeTransport{exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
		calls++
		return iso7816.Response{Status: iso7816.StatusSuccess}, nil
	}}
	d := New(raw)

	t.Cleanup(func() { _ = d.Close() })

	if err := d.lock(t.Context()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	waiting := make(chan error, 1)

	go func() {
		_, err := d.GetData(ctx, protocol.URLObject)
		waiting <- err
	}()

	cancel()

	if err := receive(t, waiting, "canceled waiter"); !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}

	d.unlock()

	if _, err := d.GetData(t.Context(), protocol.URLObject); err != nil {
		t.Fatal(err)
	}

	if calls != 1 {
		t.Errorf("exchange calls = %d, want 1", calls)
	}
}

func TestInvalidatedOperationClosesDeviceAndPreservesCauses(t *testing.T) {
	cause := errors.New("connection lost")
	closeErr := errors.New("disconnect failed")

	var closes atomic.Int32

	raw := &exchangeTransport{
		exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
			return iso7816.Response{}, &transport.DeviceInvalidatedError{Err: cause}
		},
		close: func() error {
			closes.Add(1)
			return closeErr
		},
	}
	d := New(raw)

	_, err := d.GetData(t.Context(), protocol.URLObject)

	var invalidated *transport.DeviceInvalidatedError
	if !errors.As(err, &invalidated) || !errors.Is(err, cause) || !errors.Is(err, closeErr) {
		t.Fatalf("error = %v, want invalidation, I/O cause, and close cause", err)
	}

	if _, err := d.GetData(t.Context(), protocol.URLObject); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("next operation error = %v", err)
	}

	if err := d.Close(); !errors.Is(err, closeErr) {
		t.Errorf("Close error = %v", err)
	}

	if closes.Load() != 1 {
		t.Errorf("close calls = %d, want 1", closes.Load())
	}
}
