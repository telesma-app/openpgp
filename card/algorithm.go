package card

import (
	"context"

	"github.com/telesma-app/openpgp/protocol"
)

// Algorithm Attributes (Sec. 4.4.3.9).

// GetAlgorithmAttributes reads an algorithm-attributes object. C1-C3 are read
// from Application Related Data, or individually when omitted there.
func (d *Device) GetAlgorithmAttributes(ctx context.Context, object protocol.Object) (protocol.AlgorithmAttributes, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.AlgorithmAttributes{}, err
	}
	defer d.unlock()

	attributes, err := d.client.GetAlgorithmAttributes(ctx, object)

	return attributes, d.operationError(err)
}

// PutAlgorithmAttributes atomically verifies PW3 and replaces the addressed
// algorithm attributes. Nil authentication uses the current verification state.
// The card may delete an existing key or prevent its use when attributes change;
// discard old PrivateKey bindings after acknowledged replacement. This does not
// generate keys or update fingerprints, generation times or certificates.
func (d *Device) PutAlgorithmAttributes(
	ctx context.Context,
	object protocol.Object,
	attributes protocol.AlgorithmAttributes,
	authentication AuthenticationSource,
) error {
	if err := d.lockAuthenticated(ctx, protocol.PW3, authentication); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.PutAlgorithmAttributes(ctx, object, attributes))
}

// Algorithm Information (Sec. 4.4.3.11).

// GetAlgorithmInformation reads the advertised algorithm attributes, preserving
// entry order, repeated objects and proprietary objects.
func (d *Device) GetAlgorithmInformation(ctx context.Context) ([]protocol.AlgorithmInformation, error) {
	if err := d.lock(ctx); err != nil {
		return nil, err
	}
	defer d.unlock()

	information, err := d.client.GetAlgorithmInformation(ctx)

	return information, d.operationError(err)
}

// keyAttributes requires the operation gate so the slot configuration remains
// unchanged through preparation, verification and key replacement.
func (d *Device) keyAttributes(
	ctx context.Context,
	tag protocol.ControlReferenceTemplateTag,
) (protocol.AlgorithmAttributes, error) {
	var object protocol.Object

	switch tag {
	case protocol.DigitalSignatureTemplateTag:
		object = protocol.SignatureAlgorithmAttributesObject
	case protocol.ConfidentialityTemplateTag:
		object = protocol.DecryptionAlgorithmAttributesObject
	case protocol.AuthenticationTemplateTag:
		object = protocol.AuthenticationAlgorithmAttributesObject
	default:
		panic("openpgp: key has no standard algorithm attributes")
	}

	return d.client.GetAlgorithmAttributes(ctx, object)
}
