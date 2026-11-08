// APDU framing, GET RESPONSE and command chaining (Secs. 7.2.9 and 7.7).
package iso7816

import (
	"context"
	"errors"
	"fmt"

	baseiso7816 "github.com/telesma-app/iso7816"
	openpgptransport "github.com/telesma-app/openpgp/transport"
)

type parameters struct {
	maxCommandAPDULength int
}

// Option configures command framing without discovering card capabilities.
type Option func(*parameters)

// WithMaxCommandAPDULength sets the maximum total bytes in each command APDU,
// including its header, length fields and any secure messaging envelope. Use
// the card's Extended Length Information (7F66); the default is 256 bytes
// (Sec. 4.1.3.1). Length must allow at least a five-byte GET RESPONSE command.
// Commands exceeding the limit use chaining in their requested encoding.
func WithMaxCommandAPDULength(length int) Option {
	return func(parameters *parameters) {
		parameters.maxCommandAPDULength = length
	}
}

func commandParameters(options []Option) parameters {
	parameters := parameters{maxCommandAPDULength: 256}
	for _, option := range options {
		option(&parameters)
	}

	return parameters
}

// Exchange borrows card and collects GET RESPONSE data using CLA 00. Commands
// are chained to fit the total APDU limit, 256 bytes by default. Explicit
// extended encoding is preserved; other commands use short encoding. Rejected
// fragments return an APDUError; the final status word is returned unchanged.
// Callers establish the required card state, serialize exchanges and close card
// after DeviceInvalidatedError. Cancellation before I/O preserves the card;
// interruption after I/O invalidates it.
func Exchange(ctx context.Context, rawCard baseiso7816.Card, command baseiso7816.Command, options ...Option) (baseiso7816.Response, error) {
	return exchangeCommand(ctx, rawCard, command, commandParameters(options))
}

func exchangeCommand(ctx context.Context, rawCard baseiso7816.Card, command baseiso7816.Command, parameters parameters) (baseiso7816.Response, error) {
	if err := ctx.Err(); err != nil {
		return baseiso7816.Response{}, err
	}

	if parameters.maxCommandAPDULength < 5 {
		return baseiso7816.Response{}, fmt.Errorf("%w: maximum command APDU length %d cannot hold GET RESPONSE", baseiso7816.ErrInvalidFragmentSize, parameters.maxCommandAPDULength)
	}

	if command.Encoding == baseiso7816.EncodingAuto {
		command.Encoding = baseiso7816.EncodingShort
	}

	commands, err := baseiso7816.Chain(command, parameters.maxCommandAPDULength)
	if err != nil {
		return baseiso7816.Response{}, err
	}

	card := &ioCard{Card: rawCard}

	response, err := baseiso7816.ExchangeChain(ctx, card, commands, baseiso7816.WithGetResponseCLA(0))
	if err != nil {
		return baseiso7816.Response{}, card.exchangeError(err)
	}

	return response, nil
}

type ioCard struct {
	baseiso7816.Card
	started bool
}

func (c *ioCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	c.started = true

	response, err := c.Card.Transmit(ctx, apdu)
	if err != nil {
		return response, &openpgptransport.IOError{Operation: openpgptransport.IOTransmit, Err: err}
	}

	return response, nil
}

func (c *ioCard) exchangeError(err error) error {
	var apduError *baseiso7816.APDUError
	if errors.As(err, &apduError) {
		if _, moreData := apduError.StatusWord().MoreDataLength(); !moreData {
			return err
		}
		// An intermediate fragment must acknowledge receipt, not start a
		// response while the command chain is incomplete.
		err = baseiso7816.ErrInvalidResponse
	}

	if c.started {
		return &openpgptransport.DeviceInvalidatedError{Err: err}
	}

	return err
}
