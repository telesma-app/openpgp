package client

import (
	"context"

	"github.com/telesma-app/openpgp/protocol"
)

// DF.OpenPGP (Sec. 4.2) and its data objects (Sec. 4.4).

// GetApplicationIdentifier reads the full sixteen-byte OpenPGP AID.
func (c *Client) GetApplicationIdentifier(ctx context.Context) (protocol.ApplicationIdentifier, error) {
	data, err := c.GetData(ctx, protocol.ApplicationIdentifierObject)
	if err != nil {
		return protocol.ApplicationIdentifier{}, err
	}

	return protocol.ParseApplicationIdentifier(data)
}

// GetApplicationRelatedData reads the application metadata template, including
// capabilities, algorithm attributes, password status and key metadata.
func (c *Client) GetApplicationRelatedData(ctx context.Context) (protocol.ApplicationRelatedData, error) {
	data, err := c.GetData(ctx, protocol.ApplicationRelatedDataObject)
	if err != nil {
		return protocol.ApplicationRelatedData{}, err
	}

	return protocol.ParseApplicationRelatedData(data)
}

// GetCardholderRelatedData reads the cardholder's name, language and sex data.
func (c *Client) GetCardholderRelatedData(ctx context.Context) (protocol.CardholderRelatedData, error) {
	data, err := c.GetData(ctx, protocol.CardholderRelatedDataObject)
	if err != nil {
		return protocol.CardholderRelatedData{}, err
	}

	return protocol.ParseCardholderRelatedData(data)
}

// GetSecuritySupportTemplate reads the digital-signature counter.
func (c *Client) GetSecuritySupportTemplate(ctx context.Context) (protocol.SecuritySupportTemplate, error) {
	data, err := c.GetData(ctx, protocol.SecuritySupportTemplateObject)
	if err != nil {
		return protocol.SecuritySupportTemplate{}, err
	}

	return protocol.ParseSecuritySupportTemplate(data)
}
