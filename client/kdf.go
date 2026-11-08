package client

import (
	"context"

	"github.com/telesma-app/openpgp/protocol"
)

// GetKDF reads the password and resetting-code KDF data object (Sec. 4.3.2).
// It does not transform passwords or change their encoding.
func (c *Client) GetKDF(ctx context.Context) (protocol.KDF, error) {
	data, err := c.GetData(ctx, protocol.KDFObject)
	if err != nil {
		return protocol.KDF{}, err
	}

	return protocol.ParseKDF(data)
}

// PutKDF replaces the KDF data object after PW3 verification (Sec. 4.3.2).
// The caller coordinates PW1, PW3 and resetting-code state with the new KDF.
// This sends only PUT DATA, without deriving passwords or issuing password
// commands. Input slices are borrowed unchanged.
func (c *Client) PutKDF(ctx context.Context, kdf protocol.KDF) error {
	data := protocol.EncodeKDF(kdf)
	defer clear(data)

	return c.PutData(ctx, protocol.KDFObject, data)
}
