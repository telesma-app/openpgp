package sm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport"
)

// Parameters supplies the card's static keys and protected APDU encoding.
// Encoding must be EncodingShort (with chaining) or EncodingExtended.
// MACLength is 8 by default; 16 selects a full-length cryptogram.
type Parameters struct {
	Keys      Keys
	Encoding  iso7816.Encoding
	MACLength int
}

// Transport owns a static-key secure messaging connection. Create it with New,
// stop using the underlying connection directly, and do not copy it.
type Transport struct {
	connection     transport.Device
	session        recordSession
	initialization bool
	mu             chan struct{}
	cryptoMu       sync.Mutex
	closed         chan struct{}
	closeOnce      sync.Once
	closeErr       error
}

var _ transport.Device = (*Transport)(nil)

// New wraps a selected OpenPGP connection without I/O. The caller establishes
// support for the static-key AES algorithm matching parameters.Keys. New neither
// authenticates the card nor provisions keys; response authentication follows
// the package contract. It copies the keys and takes ownership of connection
// only on success.
func New(connection transport.Device, parameters Parameters) (*Transport, error) {
	session, err := newRecordSession(parameters.Keys, parameters.Encoding, parameters.MACLength)
	if err != nil {
		return nil, err
	}

	return &Transport{
		connection: connection,
		session:    session,
		mu:         make(chan struct{}, 1),
		closed:     make(chan struct{}),
	}, nil
}

// Exchange obtains a fresh challenge and protects one command under the same
// gate. Plaintext commands and response authentication follow the package
// contract. Commands must leave OpenPGP selected. The underlying transport
// handles fragmentation and GET RESPONSE. After acknowledged termination,
// ACTIVATE FILE runs in plaintext and closes the connection only on success.
func (t *Transport) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	if err := t.lock(ctx); err != nil {
		return iso7816.Response{}, err
	}
	defer func() { <-t.mu }()

	t.cryptoMu.Lock()
	if !t.isOpen() {
		t.cryptoMu.Unlock()
		return iso7816.Response{}, io.ErrClosedPipe
	}

	err := t.session.validateCommand(command)
	t.cryptoMu.Unlock()

	if err != nil {
		return iso7816.Response{}, err
	}

	activating := t.initialization && command.INS == byte(protocol.ActivateFile)
	if plainCommand(command.INS) || activating {
		response, err := t.connection.Exchange(ctx, command)
		if err != nil {
			return iso7816.Response{}, t.exchangeError(err)
		}

		if command.INS == byte(protocol.Select) && response.Status == 0x6285 {
			t.initialization = true
		}

		if activating && response.Status == iso7816.StatusSuccess {
			if len(response.Data) != 0 {
				return iso7816.Response{}, t.invalidate(fmt.Errorf("%w: data in ACTIVATE FILE response", ErrInvalidResponse))
			}

			return response, t.Close()
		}

		return response, nil
	}

	challenge, err := t.connection.Exchange(ctx, iso7816.Command{
		INS: byte(protocol.GetChallenge), Le: 16, Encoding: iso7816.EncodingShort,
	})
	if err != nil {
		return iso7816.Response{}, t.exchangeError(err)
	}

	if err := challenge.APDUError(); err != nil {
		return iso7816.Response{}, err
	}

	if len(challenge.Data) != 16 {
		return iso7816.Response{}, t.invalidate(fmt.Errorf("%w: GET CHALLENGE length %d, want 16", ErrInvalidResponse, len(challenge.Data)))
	}

	rnd := [16]byte(challenge.Data)

	if err := ctx.Err(); err != nil {
		return iso7816.Response{}, err
	}

	t.cryptoMu.Lock()
	if !t.isOpen() {
		t.cryptoMu.Unlock()
		return iso7816.Response{}, io.ErrClosedPipe
	}

	protected := t.session.protect(command, rnd)
	t.cryptoMu.Unlock()

	response, err := t.connection.Exchange(ctx, protected)
	if err != nil {
		return iso7816.Response{}, t.exchangeError(err)
	}

	t.cryptoMu.Lock()
	if !t.isOpen() {
		t.cryptoMu.Unlock()
		return iso7816.Response{}, io.ErrClosedPipe
	}

	plaintext, err := t.session.unprotect(command, response, rnd)
	retired := len(t.session.keys.ENC) == 0
	t.cryptoMu.Unlock()

	if err != nil {
		return iso7816.Response{}, t.invalidate(err)
	}

	if command.INS == byte(protocol.TerminateDF) && plaintext.Status == iso7816.StatusSuccess {
		t.initialization = true
	}

	if retired {
		return plaintext, t.Close()
	}

	return plaintext, nil
}

// Close closes the connection once without waiting for Exchange, clears owned
// key bytes and drops cipher state. Repeated calls return the same error.
func (t *Transport) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		t.closeErr = t.connection.Close()
		t.cryptoMu.Lock()
		t.session.clear()
		t.cryptoMu.Unlock()
	})

	return t.closeErr
}

func (t *Transport) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.closed:
		return io.ErrClosedPipe
	case t.mu <- struct{}{}:
	}

	if err := ctx.Err(); err != nil {
		<-t.mu
		return err
	}

	if !t.isOpen() {
		<-t.mu
		return io.ErrClosedPipe
	}

	return nil
}

func (t *Transport) isOpen() bool {
	select {
	case <-t.closed:
		return false
	default:
		return true
	}
}

func (t *Transport) exchangeError(err error) error {
	if _, invalidated := errors.AsType[*transport.DeviceInvalidatedError](err); !invalidated &&
		(errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return err
	}

	return t.invalidate(err)
}

func (t *Transport) invalidate(err error) error {
	if _, ok := errors.AsType[*transport.DeviceInvalidatedError](err); !ok {
		err = &transport.DeviceInvalidatedError{Err: err}
	}

	return errors.Join(err, t.Close())
}
