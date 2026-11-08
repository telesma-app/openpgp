package card

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport"
)

func TestCloseInterruptsActiveOperationAndReleasesWaiters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		raw := &blockingTransport{started: make(chan struct{}), closed: make(chan struct{})}
		d := New(raw)
		ctx, cancel := context.WithCancel(t.Context())

		defer func() {
			cancel()

			_ = raw.Close()
			_ = d.Close()

			synctest.Wait()
		}()

		active := make(chan error, 1)

		go func() {
			_, err := d.GetData(ctx, protocol.URLObject)
			active <- err
		}()

		receive(t, raw.started, "active exchange")

		waiting := make(chan error, 1)

		go func() {
			_, err := d.GetData(ctx, protocol.URLObject)
			waiting <- err
		}()

		synctest.Wait()

		select {
		case err := <-waiting:
			t.Fatalf("waiter returned before Close: %v", err)
		default:
		}

		closed := make(chan error, 1)

		go func() { closed <- d.Close() }()

		if err := receive(t, closed, "Close without waiting for the operation gate"); err != nil {
			t.Error(err)
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
	})
}

func TestCloseReleasesWaitersBeforeTransportCloseCompletes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		activeStarted := make(chan struct{})
		closeStarted := make(chan struct{})
		finishActive := make(chan struct{}, 1)
		finishClose := make(chan struct{}, 1)
		d := New(&exchangeTransport{
			exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
				close(activeStarted)
				<-finishActive

				return iso7816.Response{}, io.ErrClosedPipe
			},
			close: func() error {
				close(closeStarted)
				<-finishClose

				return nil
			},
		})
		ctx, cancel := context.WithCancel(t.Context())

		defer func() {
			cancel()
			close(finishClose)
			close(finishActive)

			_ = d.Close()

			synctest.Wait()
		}()

		active := make(chan error, 1)

		go func() {
			_, err := d.GetData(ctx, protocol.URLObject)
			active <- err
		}()

		receive(t, activeStarted, "active exchange")

		waiting := make(chan error, 1)

		go func() {
			_, err := d.GetData(ctx, protocol.URLObject)
			waiting <- err
		}()

		synctest.Wait()

		select {
		case err := <-waiting:
			t.Fatalf("waiter returned before Close: %v", err)
		default:
		}

		closed := make(chan error, 1)

		go func() { closed <- d.Close() }()

		receive(t, closeStarted, "transport Close starting without waiting for the operation gate")

		if err := receive(t, waiting, "waiter released before transport Close and active exchange complete"); !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("waiting error = %v", err)
		}

		synctest.Wait()

		select {
		case err := <-closed:
			t.Fatalf("Close returned before transport Close completed: %v", err)
		default:
		}

		finishClose <- struct{}{}

		if err := receive(t, closed, "Close completing while the active exchange remains blocked"); err != nil {
			t.Error(err)
		}

		select {
		case err := <-active:
			t.Fatalf("active operation returned before release: %v", err)
		default:
		}

		finishActive <- struct{}{}

		if err := receive(t, active, "active exchange completing after Close"); !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("active error = %v", err)
		}

		if _, err := d.GetData(t.Context(), protocol.URLObject); !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("closed device error = %v", err)
		}
	})
}

func TestCanceledWaitPreservesDevice(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls int

		raw := &exchangeTransport{exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
			calls++
			return iso7816.Response{Status: iso7816.StatusSuccess}, nil
		}}
		d := New(raw)

		defer func() {
			_ = d.Close()

			synctest.Wait()
		}()

		func() {
			if err := d.lock(t.Context()); err != nil {
				t.Fatal(err)
			}
			defer d.unlock()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			waiting := make(chan error, 1)

			go func() {
				_, err := d.GetData(ctx, protocol.URLObject)
				waiting <- err
			}()

			synctest.Wait()

			select {
			case err := <-waiting:
				t.Fatalf("waiter returned before cancellation: %v", err)
			default:
			}

			cancel()

			err := receive(t, waiting, "canceled waiter")

			var invalidated *transport.DeviceInvalidatedError
			if !errors.Is(err, context.Canceled) || errors.As(err, &invalidated) {
				t.Errorf("error = %v, want context.Canceled without invalidation", err)
			}

			if calls != 0 {
				t.Errorf("exchange calls while waiting = %d, want 0", calls)
			}
		}()

		if _, err := d.GetData(t.Context(), protocol.URLObject); err != nil {
			t.Fatal(err)
		}

		if calls != 1 {
			t.Errorf("exchange calls = %d, want 1", calls)
		}
	})
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
