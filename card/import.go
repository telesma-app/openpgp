package card

import (
	"context"
	"crypto"

	"github.com/telesma-app/openpgp/protocol"
)

// ImportKey reads a standard slot's attributes and prepares the import before
// verifying PW3 and replacing the key. These steps run under one gate; the
// password source runs before it. Nil authentication uses the current
// verification state. Key must be valid and is borrowed unchanged. The method
// does not configure attributes or update fingerprints, times or certificates.
// Discard old PrivateKey bindings after acknowledgement, including client.KeyImportError.
func (d *Device) ImportKey(
	ctx context.Context,
	tag protocol.ControlReferenceTemplateTag,
	key crypto.PrivateKey,
	authentication AuthenticationSource,
) error {
	password, err := d.lockForAuthentication(ctx, authentication)
	if err != nil {
		return err
	}
	defer d.unlock()
	defer clear(password)

	attributes, err := d.keyAttributes(ctx, tag)
	if err != nil {
		return d.operationError(err)
	}

	template := protocol.ControlReferenceTemplate{Tag: tag}

	data, err := protocol.EncodeKeyImport(template, attributes, key)
	if err != nil {
		return err
	}
	defer clear(data)

	if authentication != nil {
		err := d.client.Verify(ctx, protocol.PW3, password)
		clear(password)

		if err != nil {
			return d.operationError(err)
		}
	}

	return d.operationError(d.client.ImportKeyData(ctx, template, data))
}

// ImportKeyWithTemplate prepares the import before invoking the password source.
// PW3 verification and key replacement run under one gate. Nil authentication
// uses the current verification state. Attributes must describe the current
// configuration; a mismatch is rejected before authentication.
// Key must be valid and is borrowed unchanged. The method does not configure
// attributes or update key metadata.
// Discard old bindings after acknowledgement, including client.KeyImportError.
// An interrupted exchange has an unknown effect.
func (d *Device) ImportKeyWithTemplate(
	ctx context.Context,
	template protocol.ControlReferenceTemplate,
	attributes protocol.AlgorithmAttributes,
	key crypto.PrivateKey,
	authentication AuthenticationSource,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	data, err := protocol.EncodeKeyImport(template, attributes, key)
	if err != nil {
		return err
	}
	defer clear(data)

	if err := d.lockAuthenticated(ctx, protocol.PW3, authentication); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.ImportKeyData(ctx, template, data))
}
