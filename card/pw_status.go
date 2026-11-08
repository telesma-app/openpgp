package card

import (
	"context"

	"github.com/telesma-app/openpgp/protocol"
)

// GetPWStatusBytes reads password limits, retry counters, and signing policy.
func (d *Device) GetPWStatusBytes(ctx context.Context) (protocol.PWStatusBytes, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.PWStatusBytes{}, err
	}
	defer d.unlock()

	data, err := d.client.GetPWStatusBytes(ctx)

	return data, d.operationError(err)
}

// PutPWStatusBytes atomically verifies PW3 and writes the signing policy and
// optional password lengths and formats. Nil authentication uses the current
// verification state. Supply PW3 using its current encoding. Preserve reported
// maximum lengths when changing formats; the card determines supported updates.
func (d *Device) PutPWStatusBytes(
	ctx context.Context,
	update protocol.PWStatusBytesUpdate,
	authentication AuthenticationSource,
) error {
	if err := d.lockAuthenticated(ctx, protocol.PW3, authentication); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.PutPWStatusBytes(ctx, update))
}
