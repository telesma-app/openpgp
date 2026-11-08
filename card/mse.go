package card

import (
	"context"
	"errors"
	"fmt"

	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport"
)

// Temporary key bindings follow MANAGE SECURITY ENVIRONMENT (Sec. 7.2.18).

// withKey requires the operation gate and default key bindings on entry.
// It restores only the affected binding; SELECT would also reset other state.
func (d *Device) withKey(
	ctx context.Context,
	operation, tag protocol.ControlReferenceTemplateTag,
	command func() ([]byte, error),
) ([]byte, error) {
	if tag == operation {
		return command()
	}

	selected := mseKeyReference(tag)

	defaultKey := mseKeyReference(operation)
	if err := d.client.ManageSecurityEnvironment(ctx, operation, selected); err != nil {
		// An acknowledged MSE with invalid response data may have changed the binding.
		if errors.Is(err, protocol.ErrInvalidResponse) {
			return nil, &transport.DeviceInvalidatedError{Err: err}
		}

		return nil, err
	}

	data, err := command()
	if _, ok := errors.AsType[*transport.DeviceInvalidatedError](err); ok {
		return nil, err
	}

	// Restore with the caller's context; failure invalidates the connection.
	if restoreErr := d.client.ManageSecurityEnvironment(ctx, operation, defaultKey); restoreErr != nil {
		return nil, &transport.DeviceInvalidatedError{
			Err: errors.Join(err, fmt.Errorf("openpgp: restore default key binding: %w", restoreErr)),
		}
	}

	return data, err
}

func mseKeyReference(tag protocol.ControlReferenceTemplateTag) protocol.KeyReference {
	switch tag {
	case protocol.ConfidentialityTemplateTag:
		return protocol.DecryptionKeyReference
	case protocol.AuthenticationTemplateTag:
		return protocol.AuthenticationKeyReference
	default:
		panic("openpgp: MSE requires a DEC or AUT key")
	}
}
