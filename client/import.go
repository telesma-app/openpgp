package client

import (
	"context"
	"crypto"
	"fmt"

	"github.com/telesma-app/openpgp/protocol"
)

// KeyImportError reports acknowledged key replacement with unexpected response
// data. Template is the requested CRT. Retrying replaces the key again.
// Transport failures have unknown effects and do not use this type.
type KeyImportError struct {
	Template protocol.ControlReferenceTemplate
	Err      error
}

func (e *KeyImportError) Error() string {
	return fmt.Sprintf("openpgp: key CRT %x imported, but response is invalid: %v", e.Template.Bytes(), e.Err)
}

func (e *KeyImportError) Unwrap() error {
	return e.Err
}

// ImportKey reads a standard slot's attributes, then imports its key after PW3
// verification. It does not configure attributes or update fingerprints, times
// or certificates. SIG import resets the signature counter. Key is borrowed
// unchanged; encoded material is cleared. Discard old bindings after
// acknowledgement, including KeyImportError.
func (c *Client) ImportKey(
	ctx context.Context,
	tag protocol.ControlReferenceTemplateTag,
	key crypto.PrivateKey,
) error {
	attributes, err := c.keyAttributes(ctx, tag)
	if err != nil {
		return err
	}

	return c.ImportKeyWithTemplate(ctx, protocol.ControlReferenceTemplate{Tag: tag}, attributes, key)
}

// ImportKeyWithTemplate imports a key after PW3 verification (Secs. 4.4.3.12
// and 7.2.8). Attributes must describe the target's current configuration.
// Key is borrowed unchanged; the encoded payload is cleared on return.
// It does not configure attributes or update key metadata. Discard old bindings
// after acknowledgement, including KeyImportError. Transport failures have
// unknown effects.
func (c *Client) ImportKeyWithTemplate(
	ctx context.Context,
	template protocol.ControlReferenceTemplate,
	attributes protocol.AlgorithmAttributes,
	key crypto.PrivateKey,
) error {
	payload, err := protocol.EncodeKeyImport(template, attributes, key)
	if err != nil {
		return err
	}
	defer clear(payload)

	return c.ImportKeyData(ctx, template, payload)
}
