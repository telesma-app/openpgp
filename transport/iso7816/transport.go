package iso7816

import (
	"context"
	"errors"
	"io"
	"sync"

	baseiso7816 "github.com/telesma-app/iso7816"
	openpgptransport "github.com/telesma-app/openpgp/transport"
)

// Card is a closable APDU connection. Close must be safe during Transmit and
// should interrupt it when the underlying implementation supports cancellation.
type Card interface {
	baseiso7816.Card
	io.Closer
}

// Transport owns a card connection and serializes complete APDU exchanges.
// New preserves its current state; Open selects the OpenPGP application first.
type Transport struct {
	card       Card
	parameters parameters
	mu         chan struct{}
	closed     chan struct{}
	closeOnce  sync.Once
	closeErr   error
}

var _ openpgptransport.Device = (*Transport)(nil)

// New takes ownership of card without I/O. The caller stops using card directly
// and establishes the required card state. Use Open to select OpenPGP first.
func New(card Card, options ...Option) *Transport {
	return newTransportWithParameters(card, commandParameters(options))
}

// Exchange sends a complete APDU command and closes invalidated cards.
// Waiting respects ctx; Close releases waiters with io.ErrClosedPipe.
func (t *Transport) Exchange(ctx context.Context, command baseiso7816.Command) (baseiso7816.Response, error) {
	select {
	case <-ctx.Done():
		return baseiso7816.Response{}, ctx.Err()
	case <-t.closed:
		return baseiso7816.Response{}, io.ErrClosedPipe
	case t.mu <- struct{}{}:
	}

	defer func() { <-t.mu }()

	select {
	case <-t.closed:
		return baseiso7816.Response{}, io.ErrClosedPipe
	default:
	}

	response, err := exchangeCommand(ctx, t.card, command, t.parameters)

	var invalidated *openpgptransport.DeviceInvalidatedError
	if errors.As(err, &invalidated) {
		err = errors.Join(err, t.Close())
	}

	return response, err
}

// Close closes the card once without waiting for Exchange. I/O interruption
// depends on the card's cancellation support.
func (t *Transport) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)

		if err := t.card.Close(); err != nil {
			t.closeErr = &openpgptransport.IOError{Operation: openpgptransport.IOClose, Err: err}
		}
	})

	return t.closeErr
}

func newTransportWithParameters(card Card, parameters parameters) *Transport {
	return &Transport{
		card:       card,
		parameters: parameters,
		mu:         make(chan struct{}, 1),
		closed:     make(chan struct{}),
	}
}
