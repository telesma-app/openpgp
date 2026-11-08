package iso7816

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
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
			card := &gatedCard{
				requests: make(chan byte, 1),
				release:  make(chan struct{}),
				closed:   make(chan struct{}),
			}

			device, err := Open(t.Context(), card)
			if err != nil {
				t.Fatal(err)
			}

			active := make(chan error, 1)

			done := make(chan struct{})
			go func() {
				defer close(done)

				_, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0x20, P2: 0x81})
				active <- err
			}()

			t.Cleanup(func() {
				_ = device.Close()

				receive(t, done, "active Exchange did not stop")
			})

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

			if tc.want == context.Canceled {
				cancel()
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
	card := &delayedCloseCard{
		gatedCard: gatedCard{
			requests: make(chan byte, 1),
			release:  make(chan struct{}),
			closed:   make(chan struct{}),
		},
		closeStarted: make(chan struct{}),
		finishClose:  make(chan struct{}),
	}

	device, err := Open(t.Context(), card)
	if err != nil {
		t.Fatal(err)
	}

	activeCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	active := make(chan error, 1)

	go func() {
		_, err := device.Exchange(activeCtx, baseiso7816.Command{INS: 0x20, P2: 0x81})
		active <- err
	}()

	closed := make(chan error, 1)

	t.Cleanup(func() {
		close(card.finishClose)

		_ = device.Close()

		if err := receive(t, closed, "Close did not finish after card was released"); err != nil {
			t.Error(err)
		}

		if err := receive(t, active, "active Exchange did not stop after Close"); !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("active Exchange = %v, want closed pipe", err)
		}
	})
	receive(t, card.requests, "active Exchange did not start")

	queued := make(chan error, 1)

	go func() {
		_, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0xca, P2: 0x6e, Le: 256})
		queued <- err
	}()
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

func receive[T any](t testing.TB, ch <-chan T, failure string) T {
	t.Helper()

	select {
	case value := <-ch:
		return value
	case <-time.After(time.Second):
		t.Fatal(failure)

		var zero T

		return zero
	}
}
