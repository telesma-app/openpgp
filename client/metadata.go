package client

import (
	"context"

	"github.com/telesma-app/openpgp/protocol"
)

// Files and objects under the MF (Sec. 4.1).

// GetHistoricalBytes reads the selected application's historical bytes
// (Sec. 6). These may differ from the historical bytes in the card's ATR.
func (c *Client) GetHistoricalBytes(ctx context.Context) (protocol.HistoricalBytes, error) {
	data, err := c.GetData(ctx, protocol.HistoricalBytesObject)
	if err != nil {
		return protocol.HistoricalBytes{}, err
	}

	return protocol.ParseHistoricalBytes(data)
}

// GetExtendedLengthInformation reads the reported maximum total command and
// response APDU lengths, including secure messaging (Sec. 4.1.3.1).
func (c *Client) GetExtendedLengthInformation(ctx context.Context) (protocol.ExtendedLengthInformation, error) {
	data, err := c.GetData(ctx, protocol.ExtendedLengthInformationObject)
	if err != nil {
		return protocol.ExtendedLengthInformation{}, err
	}

	return protocol.ParseExtendedLengthInformation(data)
}

// GetGeneralFeatureManagement reads the optional user-interaction hardware
// flags (Sec. 4.1.3.2). An unavailable object remains an APDU error.
func (c *Client) GetGeneralFeatureManagement(ctx context.Context) (protocol.GeneralFeatureManagement, error) {
	data, err := c.GetData(ctx, protocol.GeneralFeatureManagementObject)
	if err != nil {
		return protocol.GeneralFeatureManagement{}, err
	}

	return protocol.ParseGeneralFeatureManagement(data)
}
