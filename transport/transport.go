// Package transport defines the APDU exchange boundary for OpenPGP and MF reads.
package transport

import (
	"context"
	"io"

	"github.com/telesma-app/iso7816"
)

// APDU exchanges complete commands with chaining and GET RESPONSE. The caller
// establishes the required card state. Rejected intermediate fragments return
// an iso7816.APDUError; the final status word is returned unchanged.
// Cancellation before I/O preserves the connection; interruption after I/O
// must return DeviceInvalidatedError.
type APDU interface {
	Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error)
}

// Device is an owned OpenPGP connection. Close must be safe alongside Exchange.
type Device interface {
	APDU
	io.Closer
}

// IOOperation identifies the failed underlying card operation.
type IOOperation string

const (
	IOTransmit IOOperation = "transmit"
	IOClose    IOOperation = "close"
)

// IOError identifies a card I/O failure and preserves its cause.
type IOError struct {
	Operation IOOperation
	Err       error
}

func (e *IOError) Error() string {
	return "transport " + string(e.Operation) + ": " + e.Err.Error()
}

func (e *IOError) Unwrap() error {
	return e.Err
}

// DeviceInvalidatedError marks a connection that must not be reused. Owned
// transports close the card before returning; borrowed card users must close it.
type DeviceInvalidatedError = iso7816.DeviceInvalidatedError
