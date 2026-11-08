package card

import (
	"context"

	"github.com/telesma-app/openpgp/protocol"
)

// GetCardholderCertificate atomically selects and reads opaque certificate
// bytes for the SIG, DEC or AUT template tag. Empty contents succeed; unavailable
// objects return an iso7816.APDUError. The selected occurrence remains current.
func (d *Device) GetCardholderCertificate(
	ctx context.Context,
	tag protocol.ControlReferenceTemplateTag,
) ([]byte, error) {
	if err := d.lock(ctx); err != nil {
		return nil, err
	}
	defer d.unlock()

	data, err := d.client.GetCardholderCertificate(ctx, tag)

	return data, d.operationError(err)
}

// GetCardholderCertificates atomically reads AUT, DEC and SIG, including empty
// certificates. SIG remains current on success. Errors return a zero result
// but may leave the cursor advanced.
func (d *Device) GetCardholderCertificates(ctx context.Context) (protocol.CardholderCertificates, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.CardholderCertificates{}, err
	}
	defer d.unlock()

	certificates, err := d.client.GetCardholderCertificates(ctx)

	return certificates, d.operationError(err)
}

// PutCardholderCertificate atomically verifies PW3, selects and replaces the
// certificate for the SIG, DEC or AUT template tag. Nil authentication uses the
// current verification state. Data is borrowed; empty data clears the contents.
// The selected occurrence remains current.
func (d *Device) PutCardholderCertificate(
	ctx context.Context,
	tag protocol.ControlReferenceTemplateTag,
	data []byte,
	authentication AuthenticationSource,
) error {
	if err := d.lockAuthenticated(ctx, protocol.PW3, authentication); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.PutCardholderCertificate(ctx, tag, data))
}
