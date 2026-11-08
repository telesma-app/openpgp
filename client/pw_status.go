package client

import (
	"context"

	"github.com/telesma-app/openpgp/protocol"
)

// GetPWStatusBytes reads the password limits, retry counters and signing policy.
func (c *Client) GetPWStatusBytes(ctx context.Context) (protocol.PWStatusBytes, error) {
	data, err := c.GetData(ctx, protocol.PWStatusBytesObject)
	if err != nil {
		return protocol.PWStatusBytes{}, err
	}

	return protocol.ParsePWStatusBytes(data)
}

// PutPWStatusBytes writes the signing policy and optional password lengths and
// formats after PW3 verification (Sec. 4.4.2). Preserve the reported maximum
// lengths when changing formats; the card determines which updates it supports.
func (c *Client) PutPWStatusBytes(ctx context.Context, update protocol.PWStatusBytesUpdate) error {
	return c.PutData(ctx, protocol.PWStatusBytesObject, protocol.EncodePWStatusBytesUpdate(update))
}
