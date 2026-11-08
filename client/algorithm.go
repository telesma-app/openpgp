package client

import (
	"context"

	"github.com/telesma-app/openpgp/protocol"
)

// Algorithm Attributes (Sec. 4.4.3.9).

// GetAlgorithmAttributes reads the current attributes of an algorithm-attributes
// object (Sec. 4.4.3.9). C1-C3 are read from Application Related Data, with an
// individual GET DATA when omitted there. Other objects are read directly.
func (c *Client) GetAlgorithmAttributes(ctx context.Context, object protocol.Object) (protocol.AlgorithmAttributes, error) {
	switch object {
	case protocol.SignatureAlgorithmAttributesObject, protocol.DecryptionAlgorithmAttributesObject, protocol.AuthenticationAlgorithmAttributesObject:
		application, err := c.GetApplicationRelatedData(ctx)
		if err != nil {
			return protocol.AlgorithmAttributes{}, err
		}

		var attributes protocol.AlgorithmAttributes

		switch object {
		case protocol.SignatureAlgorithmAttributesObject:
			attributes = application.SignatureAlgorithmAttributes
		case protocol.DecryptionAlgorithmAttributesObject:
			attributes = application.DecryptionAlgorithmAttributes
		case protocol.AuthenticationAlgorithmAttributesObject:
			attributes = application.AuthenticationAlgorithmAttributes
		}

		if attributes.Raw != nil {
			return attributes, nil
		}
	}

	data, err := c.GetData(ctx, object)
	if err != nil {
		return protocol.AlgorithmAttributes{}, err
	}

	return protocol.ParseAlgorithmAttributes(data)
}

// PutAlgorithmAttributes replaces an algorithm-attributes object after PW3
// verification (Sec. 4.4.3.9). The card decides which values it supports and may
// delete an existing key or prevent its use if the new attributes do not match.
// Discard old PrivateKey bindings after acknowledged replacement. This does not
// generate keys or update fingerprints, generation times or certificates.
func (c *Client) PutAlgorithmAttributes(ctx context.Context, object protocol.Object, attributes protocol.AlgorithmAttributes) error {
	return c.PutData(ctx, object, protocol.EncodeAlgorithmAttributes(attributes))
}

// Algorithm Information (Sec. 4.4.3.11).

// GetAlgorithmInformation reads the advertised algorithm attributes, preserving
// entry order, repeated objects and proprietary objects (Sec. 4.4.3.11).
func (c *Client) GetAlgorithmInformation(ctx context.Context) ([]protocol.AlgorithmInformation, error) {
	data, err := c.GetData(ctx, protocol.AlgorithmInformationObject)
	if err != nil {
		return nil, err
	}

	return protocol.ParseAlgorithmInformation(data)
}

func (c *Client) keyAttributes(
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

	return c.GetAlgorithmAttributes(ctx, object)
}
