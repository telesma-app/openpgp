package card

import (
	"context"

	"github.com/telesma-app/openpgp/protocol"
)

// GetUserInteractionFlag reads a User Interaction Flag object's state and
// hardware features, retaining unknown values. D6-D8 are read from Application
// Related Data, or individually when omitted there.
func (d *Device) GetUserInteractionFlag(ctx context.Context, object protocol.Object) (protocol.UserInteractionFlag, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.UserInteractionFlag{}, err
	}
	defer d.unlock()

	flag, err := d.client.GetUserInteractionFlag(ctx, object)

	return flag, d.operationError(err)
}

// PutUserInteractionFlag atomically verifies PW3 and writes the supplied State
// and Features. Nil authentication uses the current verification state. On
// cards supporting UIFPermanentlyEnabled, that state prevents further changes
// until a factory reset.
func (d *Device) PutUserInteractionFlag(
	ctx context.Context,
	object protocol.Object,
	flag protocol.UserInteractionFlag,
	authentication AuthenticationSource,
) error {
	if err := d.lockAuthenticated(ctx, protocol.PW3, authentication); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.PutUserInteractionFlag(ctx, object, flag))
}
