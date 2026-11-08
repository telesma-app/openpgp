package card

import (
	"context"

	"github.com/telesma-app/openpgp/protocol"
)

// GetKDF reads the password and resetting-code KDF data object.
func (d *Device) GetKDF(ctx context.Context) (protocol.KDF, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.KDF{}, err
	}
	defer d.unlock()

	kdf, err := d.client.GetKDF(ctx)

	return kdf, d.operationError(err)
}

// PutKDF atomically verifies PW3 and replaces the KDF data object.
// Nil authentication uses the current verification state. The caller
// coordinates PW1, PW3 and resetting-code state with the new KDF. This sends
// PUT DATA without deriving passwords or sending password-change commands.
// Input slices are borrowed unchanged.
func (d *Device) PutKDF(ctx context.Context, kdf protocol.KDF, authentication AuthenticationSource) error {
	if err := d.lockAuthenticated(ctx, protocol.PW3, authentication); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.PutKDF(ctx, kdf))
}
