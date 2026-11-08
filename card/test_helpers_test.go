package card

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport"
)

type exchangeTransport struct {
	exchange func(context.Context, iso7816.Command) (iso7816.Response, error)
	close    func() error
}

func (t *exchangeTransport) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	return t.exchange(ctx, command)
}

func (t *exchangeTransport) Close() error {
	if t.close != nil {
		return t.close()
	}

	return nil
}

func receive[T any](t testing.TB, ch <-chan T, phase string) T {
	t.Helper()

	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", phase)

		var zero T

		return zero
	}
}

type blockingTransport struct {
	started   chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func (t *blockingTransport) Exchange(context.Context, iso7816.Command) (iso7816.Response, error) {
	close(t.started)
	<-t.closed

	return iso7816.Response{}, io.ErrClosedPipe
}

func (t *blockingTransport) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	return nil
}

func newGetterTestDevice(t testing.TB, object protocol.Object, data []byte) *Device {
	t.Helper()

	var calls int

	d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
		calls++

		if command.INS != 0xca || command.P1 != byte(object>>8) || command.P2 != byte(object) || len(command.Data) != 0 {
			t.Errorf("command = %+v, want GET DATA %04x", command, uint16(object))
		}

		return success(data), nil
	}})

	t.Cleanup(func() {
		_ = d.Close()

		if calls != 1 {
			t.Errorf("exchanges = %d, want 1", calls)
		}
	})

	return d
}

func checkOperationLifecycle(t *testing.T, data []byte, call func(context.Context, *Device) error) {
	t.Helper()

	callOnce := func(t *testing.T, ctx context.Context, d *Device) error {
		t.Helper()

		completed := make(chan error, 1)
		done := make(chan struct{})

		go func() {
			defer close(done)

			completed <- call(ctx, d)
		}()

		t.Cleanup(func() { receive(t, done, "operation worker completion") })

		return receive(t, completed, "operation completion")
	}

	for _, test := range []struct {
		name        string
		canceled    bool
		invalidated bool
	}{
		{name: "canceled before I/O", canceled: true},
		{name: "ordinary transport failure"},
		{name: "connection invalidated", invalidated: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cause := errors.New("operation transport failed")
				closeCause := errors.New("operation close failed")

				exchangeError := cause
				if test.invalidated {
					exchangeError = &transport.DeviceInvalidatedError{Err: cause}
				}

				var calls, closes int

				d := New(&exchangeTransport{
					exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
						calls++

						if calls == 1 && !test.canceled {
							return iso7816.Response{}, exchangeError
						}

						return success(data), nil
					},
					close: func() error {
						closes++

						if test.invalidated {
							return closeCause
						}

						return nil
					},
				})
				ctx, cancel := context.WithCancel(t.Context())

				defer func() {
					cancel()

					_ = d.Close()
				}()

				if test.canceled {
					cancel()
				}

				err := callOnce(t, ctx, d)

				var invalidated *transport.DeviceInvalidatedError
				switch {
				case test.canceled:
					if !errors.Is(err, context.Canceled) || errors.As(err, &invalidated) || calls != 0 || closes != 0 {
						t.Errorf("canceled operation = %v, exchanges=%d closes=%d; want cancellation without I/O", err, calls, closes)
					}
				case test.invalidated:
					if !errors.As(err, &invalidated) || !errors.Is(err, cause) || !errors.Is(err, closeCause) || calls != 1 || closes != 1 {
						t.Errorf("invalidated operation = %v, exchanges=%d closes=%d; want both causes and one close", err, calls, closes)
					}
				default:
					if !errors.Is(err, cause) || errors.As(err, &invalidated) || calls != 1 || closes != 0 {
						t.Errorf("failed operation = %v, exchanges=%d closes=%d; want ordinary failure without closing", err, calls, closes)
					}
				}

				err = callOnce(t, t.Context(), d)
				if test.invalidated {
					if !errors.Is(err, io.ErrClosedPipe) || calls != 1 || closes != 1 {
						t.Errorf("operation after invalidation = %v, exchanges=%d closes=%d; want closed without I/O", err, calls, closes)
					}

					if err := d.Close(); !errors.Is(err, closeCause) || closes != 1 {
						t.Errorf("repeated Close = %v, closes=%d; want original cause and one close", err, closes)
					}
				} else {
					wantCalls := 2
					if test.canceled {
						wantCalls = 1
					}

					if err != nil || calls != wantCalls || closes != 0 {
						t.Errorf("operation reuse = %v, exchanges=%d closes=%d; want %d exchanges without closing", err, calls, closes, wantCalls)
					}
				}
			})
		})
	}

	t.Run("waits for gate", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var calls, closes int

			d := New(&exchangeTransport{
				exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
					calls++
					return success(data), nil
				},
				close: func() error { closes++; return nil },
			})
			ctx, cancel := context.WithCancel(t.Context())

			defer func() {
				cancel()

				_ = d.Close()
			}()

			completed := make(chan error, 1)
			done := make(chan struct{})

			t.Cleanup(func() { receive(t, done, "queued operation worker completion") })

			func() {
				if err := d.lock(t.Context()); err != nil {
					t.Fatal(err)
				}
				defer d.unlock()

				go func() {
					defer close(done)

					completed <- call(ctx, d)
				}()

				synctest.Wait()

				if calls != 0 {
					t.Errorf("exchanges while gate held = %d, want 0", calls)
				}

				select {
				case err := <-completed:
					t.Fatalf("operation returned while gate held: %v", err)
				default:
				}
			}()

			if err := receive(t, completed, "operation after gate release"); err != nil {
				t.Error(err)
			}

			if err := callOnce(t, ctx, d); err != nil {
				t.Error(err)
			}

			if calls != 2 || closes != 0 {
				t.Errorf("operation exchanges=%d closes=%d, want two operations without closing", calls, closes)
			}
		})
	})
}
