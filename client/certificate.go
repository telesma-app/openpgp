package client

import (
	"context"

	"github.com/telesma-app/openpgp/protocol"
)

// GetCardholderCertificate selects and reads opaque certificate bytes for the
// SIG, DEC or AUT template tag. Empty contents succeed; unavailable objects
// return an iso7816.APDUError. The selected occurrence remains current.
func (c *Client) GetCardholderCertificate(
	ctx context.Context,
	tag protocol.ControlReferenceTemplateTag,
) ([]byte, error) {
	if err := c.SelectData(ctx, protocol.CardholderCertificateObject, certificateOccurrence(tag)); err != nil {
		return nil, err
	}

	return c.GetData(ctx, protocol.CardholderCertificateObject)
}

// GetCardholderCertificates selects AUT and reads AUT, DEC and SIG, including
// empty certificates. SIG remains current on success. Errors return no partial
// result but may leave the cursor advanced.
func (c *Client) GetCardholderCertificates(ctx context.Context) (protocol.CardholderCertificates, error) {
	authentication, err := c.GetCardholderCertificate(ctx, protocol.AuthenticationTemplateTag)
	if err != nil {
		return protocol.CardholderCertificates{}, err
	}

	decryption, err := c.GetNextData(ctx)
	if err != nil {
		return protocol.CardholderCertificates{}, err
	}

	signature, err := c.GetNextData(ctx)
	if err != nil {
		return protocol.CardholderCertificates{}, err
	}

	return protocol.CardholderCertificates{
		Authentication: authentication,
		Decryption:     decryption,
		Signature:      signature,
	}, nil
}

// PutCardholderCertificate selects and replaces the certificate for the SIG,
// DEC or AUT template tag after PW3 verification. Data is borrowed; empty data
// clears the contents. The selected occurrence remains current.
func (c *Client) PutCardholderCertificate(
	ctx context.Context,
	tag protocol.ControlReferenceTemplateTag,
	data []byte,
) error {
	if err := c.SelectData(ctx, protocol.CardholderCertificateObject, certificateOccurrence(tag)); err != nil {
		return err
	}

	return c.PutData(ctx, protocol.CardholderCertificateObject, data)
}

func certificateOccurrence(tag protocol.ControlReferenceTemplateTag) byte {
	switch tag {
	case protocol.AuthenticationTemplateTag:
		return 0
	case protocol.ConfidentialityTemplateTag:
		return 1
	case protocol.DigitalSignatureTemplateTag:
		return 2
	default:
		panic("openpgp: key has no standard cardholder certificate")
	}
}
