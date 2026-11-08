package card

import (
	"context"

	"github.com/telesma-app/openpgp/protocol"
)

// GetHistoricalBytes reads the selected application's historical bytes.
func (d *Device) GetHistoricalBytes(ctx context.Context) (protocol.HistoricalBytes, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.HistoricalBytes{}, err
	}
	defer d.unlock()

	historical, err := d.client.GetHistoricalBytes(ctx)

	return historical, d.operationError(err)
}

// GetExtendedLengthInformation reads the reported maximum total command and
// response APDU lengths, including secure messaging.
func (d *Device) GetExtendedLengthInformation(ctx context.Context) (protocol.ExtendedLengthInformation, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.ExtendedLengthInformation{}, err
	}
	defer d.unlock()

	lengths, err := d.client.GetExtendedLengthInformation(ctx)

	return lengths, d.operationError(err)
}

// GetGeneralFeatureManagement reads the optional user-interaction hardware flags.
func (d *Device) GetGeneralFeatureManagement(ctx context.Context) (protocol.GeneralFeatureManagement, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.GeneralFeatureManagement{}, err
	}
	defer d.unlock()

	features, err := d.client.GetGeneralFeatureManagement(ctx)

	return features, d.operationError(err)
}
