package iso7816

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"

	baseiso7816 "github.com/telesma-app/iso7816"
	openpgptransport "github.com/telesma-app/openpgp/transport"
)

type gatedCard struct {
	requests chan byte
	release  chan struct{}
	closed   chan struct{}
}

func (c *gatedCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	if bytes.Equal(apdu, selectAPDU) {
		return selectResponse, nil
	}

	select {
	case c.requests <- apdu[1]:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, io.ErrClosedPipe
	}

	select {
	case <-c.release:
		return []byte{0x90, 0x00}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, io.ErrClosedPipe
	}
}

func (c *gatedCard) Close() error {
	close(c.closed)
	return nil
}

func TestQueuedExchangeCancellationPreservesActiveCard(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  func(context.Context) (context.Context, context.CancelFunc)
		want error
	}{
		{name: "canceled", ctx: context.WithCancel, want: context.Canceled},
		{
			name: "deadline",
			ctx: func(parent context.Context) (context.Context, context.CancelFunc) {
				return context.WithTimeout(parent, 10*time.Millisecond)
			},
			want: context.DeadlineExceeded,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				card := &gatedCard{
					requests: make(chan byte, 1),
					release:  make(chan struct{}),
					closed:   make(chan struct{}),
				}

				device, err := Open(t.Context(), card)
				if err != nil {
					t.Fatal(err)
				}

				activeCtx, cancelActive := context.WithCancel(t.Context())

				defer func() {
					cancelActive()

					_ = device.Close()

					synctest.Wait()
				}()

				active := make(chan error, 1)

				go func() {
					_, err := device.Exchange(activeCtx, baseiso7816.Command{INS: 0x20, P2: 0x81})
					active <- err
				}()

				if instruction := receive(t, card.requests, "active Exchange did not start"); instruction != 0x20 {
					t.Fatalf("instruction = %02x, want 20", instruction)
				}

				ctx, cancel := tc.ctx(t.Context())
				defer cancel()

				queued := make(chan error, 1)

				go func() {
					_, err := device.Exchange(ctx, baseiso7816.Command{INS: 0xca, P2: 0x6e, Le: 256})
					queued <- err
				}()

				synctest.Wait()

				select {
				case err := <-queued:
					t.Fatalf("queued Exchange returned before cancellation: %v", err)
				default:
				}

				select {
				case instruction := <-card.requests:
					t.Fatalf("queued Exchange transmitted instruction %02x before cancellation", instruction)
				default:
				}

				if tc.want == context.Canceled {
					cancel()
				} else {
					// Advance virtual time only after the queued Exchange is blocked.
					time.Sleep(10 * time.Millisecond)
				}

				err = receive(t, queued, "queued Exchange waited for active Exchange after cancellation")

				var invalidated *openpgptransport.DeviceInvalidatedError
				if !errors.Is(err, tc.want) || errors.As(err, &invalidated) {
					t.Fatalf("queued Exchange = %v, want cancellation without invalidation", err)
				}

				select {
				case <-card.closed:
					t.Fatal("queued cancellation closed active card")
				default:
				}

				select {
				case instruction := <-card.requests:
					t.Fatalf("queued Exchange transmitted instruction %02x", instruction)
				default:
				}

				select {
				case err := <-active:
					t.Fatalf("active Exchange returned before release: %v", err)
				default:
				}

				close(card.release)

				if err := receive(t, active, "active Exchange did not finish"); err != nil {
					t.Fatal(err)
				}

				response, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0x84, Le: 256})
				if err != nil || response.Status != 0x9000 {
					t.Fatalf("Exchange after queued cancellation = %s, %v; want success", response.Status, err)
				}

				if instruction := receive(t, card.requests, "reused card did not transmit"); instruction != 0x84 {
					t.Errorf("instruction = %02x, want 84", instruction)
				}
			})
		})
	}
}

type delayedCloseCard struct {
	gatedCard
	closeStarted chan struct{}
	finishClose  chan struct{}
}

func (c *delayedCloseCard) Close() error {
	close(c.closeStarted)
	<-c.finishClose

	return c.gatedCard.Close()
}

func TestCloseReleasesQueuedExchangeBeforeCardCloseCompletes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		card := &delayedCloseCard{
			gatedCard: gatedCard{
				requests: make(chan byte, 1),
				release:  make(chan struct{}),
				closed:   make(chan struct{}),
			},
			closeStarted: make(chan struct{}),
			finishClose:  make(chan struct{}, 1),
		}

		device, err := Open(t.Context(), card)
		if err != nil {
			t.Fatal(err)
		}

		activeCtx, cancel := context.WithCancel(t.Context())

		defer func() {
			close(card.finishClose)
			cancel()

			_ = device.Close()

			synctest.Wait()
		}()

		active := make(chan error, 1)

		go func() {
			_, err := device.Exchange(activeCtx, baseiso7816.Command{INS: 0x20, P2: 0x81})
			active <- err
		}()

		receive(t, card.requests, "active Exchange did not start")

		queued := make(chan error, 1)

		go func() {
			_, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0xca, P2: 0x6e, Le: 256})
			queued <- err
		}()

		synctest.Wait()

		select {
		case err := <-queued:
			t.Fatalf("queued Exchange returned before Close: %v", err)
		default:
		}

		select {
		case instruction := <-card.requests:
			t.Fatalf("queued Exchange transmitted instruction %02x before Close", instruction)
		default:
		}

		closed := make(chan error, 1)

		go func() { closed <- device.Close() }()

		receive(t, card.closeStarted, "Close waited for active Exchange")

		err = receive(t, queued, "queued Exchange waited for card Close to complete")

		var invalidated *openpgptransport.DeviceInvalidatedError
		if !errors.Is(err, io.ErrClosedPipe) || errors.As(err, &invalidated) {
			t.Fatalf("queued Exchange = %v, want closed pipe without invalidation", err)
		}

		select {
		case instruction := <-card.requests:
			t.Fatalf("queued Exchange transmitted instruction %02x", instruction)
		default:
		}

		select {
		case err := <-active:
			t.Fatalf("active Exchange returned before card Close completed: %v", err)
		default:
		}

		select {
		case err := <-closed:
			t.Fatalf("Close returned before card Close completed: %v", err)
		default:
		}

		card.finishClose <- struct{}{}

		if err := receive(t, closed, "Close did not finish after card was released"); err != nil {
			t.Error(err)
		}

		if err := receive(t, active, "active Exchange did not stop after Close"); !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("active Exchange = %v, want closed pipe", err)
		}
	})
}

func TestExchangeAfterCloseDoesNotTransmit(t *testing.T) {
	device, card := newTransport(t)
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}

	_, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0x20, P2: 0x81})

	var invalidated *openpgptransport.DeviceInvalidatedError
	if !errors.Is(err, io.ErrClosedPipe) || errors.As(err, &invalidated) {
		t.Fatalf("Exchange = %v, want closed pipe without invalidation", err)
	}

	if card.closeCalls != 1 {
		t.Errorf("Close calls = %d, want 1", card.closeCalls)
	}
}

func TestInterruptedChainClosesOwnedCard(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	data := bytes.Repeat([]byte{0xab}, 256)
	device, card := newTransport(t, exchange{
		request: append([]byte{0x10, 0xda, 0x00, 0x5e, 0xfb}, data[:251]...), response: []byte{0x90, 0x00}, after: cancel,
	})
	_, err := device.Exchange(ctx, baseiso7816.Command{INS: 0xda, P2: 0x5e, Data: data})

	var invalidated *openpgptransport.DeviceInvalidatedError
	if !errors.Is(err, context.Canceled) || !errors.As(err, &invalidated) {
		t.Fatalf("Exchange = %v, want invalidated cancellation", err)
	}

	if card.closeCalls != 1 {
		t.Errorf("Close calls = %d, want 1", card.closeCalls)
	}
}

func TestInterruptedGetResponseClosesOwnedCard(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	device, card := newTransport(t, exchange{
		request: []byte{0x00, 0xca, 0x00, 0x6e, 0x00}, response: []byte{0x53, 0x61, 0x01}, after: cancel,
	})
	_, err := device.Exchange(ctx, baseiso7816.Command{INS: 0xca, P2: 0x6e, Le: 256})

	var invalidated *openpgptransport.DeviceInvalidatedError
	if !errors.Is(err, context.Canceled) || !errors.As(err, &invalidated) {
		t.Fatalf("Exchange = %v, want invalidated cancellation", err)
	}

	if card.closeCalls != 1 {
		t.Errorf("Close calls = %d, want 1", card.closeCalls)
	}
}

func TestUnexpectedIntermediateResponseInvalidatesCard(t *testing.T) {
	for _, response := range [][]byte{{0x01, 0x90, 0x00}, {0x61, 0x01}, {0x9f, 0x01}} {
		data := bytes.Repeat([]byte{0xab}, 256)
		device, card := newTransport(t, exchange{
			request: append([]byte{0x10, 0xda, 0x00, 0x5e, 0xfb}, data[:251]...), response: response,
		})
		_, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0xda, P2: 0x5e, Data: data})

		var invalidated *openpgptransport.DeviceInvalidatedError
		if !errors.Is(err, baseiso7816.ErrInvalidResponse) || !errors.As(err, &invalidated) {
			t.Fatalf("response %x: Exchange = %v, want invalid response and invalidation", response, err)
		}

		if card.closeCalls != 1 {
			t.Errorf("Close calls = %d, want 1", card.closeCalls)
		}
	}
}

func TestTerminalResponsePreservesCardAfterConcurrentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	device, card := newTransport(t, exchange{
		request: []byte{0x00, 0x20, 0x00, 0x81}, response: []byte{0x63, 0xc3}, after: cancel,
	})

	response, err := device.Exchange(ctx, baseiso7816.Command{INS: 0x20, P2: 0x81})
	if err != nil || response.Status != 0x63c3 {
		t.Fatalf("Exchange = %s, %v; want terminal status 63c3", response.Status, err)
	}

	if card.closeCalls != 0 {
		t.Fatal("terminal response invalidated the card")
	}

	card.exchanges = append(card.exchanges, exchange{
		request: []byte{0x00, 0x20, 0x00, 0x81}, response: []byte{0x63, 0xc3},
	})

	response, err = device.Exchange(t.Context(), baseiso7816.Command{INS: 0x20, P2: 0x81})
	if err != nil || response.Status != 0x63c3 {
		t.Fatalf("Exchange after cancellation = %s, %v; want status 63c3", response.Status, err)
	}
}

func TestExchangeFailureInvalidatesOwnedCard(t *testing.T) {
	for _, test := range []struct {
		name     string
		response []byte
		err      error
	}{
		{name: "malformed response", response: []byte{0x90}},
		{name: "I/O failure", err: io.ErrClosedPipe},
	} {
		t.Run(test.name, func(t *testing.T) {
			device, card := newTransport(t, exchange{request: []byte{0x00, 0x20, 0x00, 0x81}, response: test.response, err: test.err})
			_, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0x20, P2: 0x81})

			var invalidated *openpgptransport.DeviceInvalidatedError
			if !errors.As(err, &invalidated) {
				t.Fatalf("Exchange = %v, want invalidation", err)
			}

			if test.err != nil && !errors.Is(err, test.err) {
				t.Errorf("Exchange = %v, lost cause %v", err, test.err)
			}

			if card.closeCalls != 1 {
				t.Errorf("Close calls = %d, want 1", card.closeCalls)
			}
		})
	}
}

func TestClosePreservesTypedErrorAndRunsOnce(t *testing.T) {
	device, card := newTransport(t)
	card.closeErr = io.ErrClosedPipe

	for range 2 {
		err := device.Close()

		var ioErr *openpgptransport.IOError
		if !errors.As(err, &ioErr) || ioErr.Operation != openpgptransport.IOClose || !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("Close = %v, want typed close failure", err)
		}
	}

	if card.closeCalls != 1 {
		t.Errorf("Close calls = %d, want 1", card.closeCalls)
	}
}

type blockingCard struct {
	started chan struct{}
	closed  chan struct{}
}

func (c *blockingCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	if bytes.Equal(apdu, selectAPDU) {
		return selectResponse, nil
	}

	close(c.started)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, io.ErrClosedPipe
	}
}

func (c *blockingCard) Close() error {
	close(c.closed)
	return nil
}

func TestCloseInterruptsExchange(t *testing.T) {
	card := &blockingCard{started: make(chan struct{}), closed: make(chan struct{})}

	device, err := Open(t.Context(), card)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = device.Close() })

	result := make(chan error, 1)

	go func() {
		_, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0x20, P2: 0x81})
		result <- err
	}()

	receive(t, card.started, "Exchange did not start")

	closed := make(chan error, 1)
	go func() { closed <- device.Close() }()

	if err := receive(t, closed, "Close waited for Exchange mutex"); err != nil {
		t.Fatal(err)
	}

	if err := receive(t, result, "Exchange did not stop after Close"); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Exchange = %v, want I/O failure", err)
	}
}

func TestNewTakesOwnershipWithoutIO(t *testing.T) {
	raw := newFakeCard(t, nil)

	connection := New(raw)
	if raw.closeCalls != 0 {
		t.Fatal("New closed the card")
	}

	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}

	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := connection.Exchange(t.Context(), baseiso7816.Command{INS: 0xcb}); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("exchange after Close = %v, want closed pipe without I/O", err)
	}

	if raw.closeCalls != 1 {
		t.Errorf("card Close calls = %d, want 1", raw.closeCalls)
	}
}

func TestExchangeStopsAfterRejectedFragment(t *testing.T) {
	data := bytes.Repeat([]byte{0xab}, 256)
	device, card := newTransport(t, exchange{
		request: append([]byte{0x10, 0xda, 0x00, 0x5e, 0xfb}, data[:251]...), response: []byte{0x69, 0x82},
	})
	_, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0xda, P2: 0x5e, Data: data})

	var apduError *baseiso7816.APDUError
	if !errors.As(err, &apduError) || apduError.StatusWord() != 0x6982 {
		t.Fatalf("Exchange = %v, want APDU error 6982", err)
	}

	var invalidated *openpgptransport.DeviceInvalidatedError
	if errors.As(err, &invalidated) || card.closeCalls != 0 {
		t.Fatal("rejected fragment invalidated the card")
	}

	card.exchanges = append(card.exchanges, exchange{
		request: []byte{0x00, 0x20, 0x00, 0x81}, response: []byte{0x63, 0xc3},
	})

	response, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0x20, P2: 0x81})
	if err != nil || response.Status != 0x63c3 {
		t.Fatalf("Exchange after rejection = %s, %v; want status 63c3", response.Status, err)
	}
}

func TestPreCanceledExchangePreservesCard(t *testing.T) {
	device, card := newTransport(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := device.Exchange(ctx, baseiso7816.Command{INS: 0x20, P2: 0x81})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Exchange = %v, want context cancellation", err)
	}

	var invalidated *openpgptransport.DeviceInvalidatedError
	if errors.As(err, &invalidated) || card.closeCalls != 0 {
		t.Fatal("pre-cancellation invalidated card")
	}
}

func TestExchangeRejectsOversizedResponse(t *testing.T) {
	response := append(bytes.Repeat([]byte{0xab}, 65537), 0x90, 0x00)
	device, card := newTransport(t, exchange{
		request: []byte{0x00, 0xca, 0x00, 0x6e, 0x00}, response: response,
	})
	_, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0xca, P2: 0x6e, Le: 256})

	var invalidated *openpgptransport.DeviceInvalidatedError
	if !errors.Is(err, baseiso7816.ErrResponseTooLarge) || !errors.As(err, &invalidated) {
		t.Fatalf("Exchange = %v, want oversized response and invalidation", err)
	}

	if card.closeCalls != 1 {
		t.Errorf("Close calls = %d, want 1", card.closeCalls)
	}
}
