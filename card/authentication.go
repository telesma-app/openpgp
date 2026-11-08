package card

import (
	"context"

	"github.com/telesma-app/openpgp/protocol"
)

// AuthenticationSource supplies a password in the card's encoding, including any KDF.
// It runs before the operation gate, may call Device methods, and may be called
// concurrently. The operation determines the password reference; generic data
// operations take it explicitly. Nil skips VERIFY and uses the current
// verification state.
//
// On success, the operation owns and clears the returned buffer before returning,
// including after cancellation. The source must stop using it. On error, the
// source retains ownership.
type AuthenticationSource func(context.Context) ([]byte, error)

// lockAuthenticated keeps VERIFY and the following operation under one gate.
// On success, the caller holds the gate and must unlock it after the workflow.
func (d *Device) lockAuthenticated(
	ctx context.Context,
	reference protocol.PasswordReference,
	authentication AuthenticationSource,
) error {
	password, err := d.lockForAuthentication(ctx, authentication)
	if err != nil {
		return err
	}
	defer clear(password)

	if authentication != nil {
		if err := d.client.Verify(ctx, reference, password); err != nil {
			err = d.operationError(err)
			d.unlock()

			return err
		}
	}

	return nil
}

// lockForAuthentication obtains the password before acquiring the operation gate.
// On success, the caller owns the password buffer and holds the gate. It must
// clear the password and unlock the gate after the workflow.
func (d *Device) lockForAuthentication(
	ctx context.Context,
	authentication AuthenticationSource,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var password []byte

	if authentication != nil {
		var err error

		password, err = authentication(ctx)
		if err != nil {
			return nil, err
		}
	}

	if err := d.lock(ctx); err != nil {
		clear(password)
		return nil, err
	}

	return password, nil
}
