package card

import (
	"context"

	"github.com/telesma-app/openpgp/protocol"
)

// Application Identifier (Sec. 4.2.1).

// GetApplicationIdentifier reads the card's full OpenPGP AID.
func (d *Device) GetApplicationIdentifier(ctx context.Context) (protocol.ApplicationIdentifier, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.ApplicationIdentifier{}, err
	}
	defer d.unlock()

	data, err := d.client.GetApplicationIdentifier(ctx)

	return data, d.operationError(err)
}

// Application and cardholder data objects (Secs. 4.4.1 and 4.4.3.1).

// GetApplicationRelatedData reads capabilities, algorithms, and key metadata.
func (d *Device) GetApplicationRelatedData(ctx context.Context) (protocol.ApplicationRelatedData, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.ApplicationRelatedData{}, err
	}
	defer d.unlock()

	data, err := d.client.GetApplicationRelatedData(ctx)

	return data, d.operationError(err)
}

// GetCardholderRelatedData reads the cardholder's name, language, and sex data.
func (d *Device) GetCardholderRelatedData(ctx context.Context) (protocol.CardholderRelatedData, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.CardholderRelatedData{}, err
	}
	defer d.unlock()

	data, err := d.client.GetCardholderRelatedData(ctx)

	return data, d.operationError(err)
}

// GetSecuritySupportTemplate reads the digital-signature counter.
func (d *Device) GetSecuritySupportTemplate(ctx context.Context) (protocol.SecuritySupportTemplate, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.SecuritySupportTemplate{}, err
	}
	defer d.unlock()

	data, err := d.client.GetSecuritySupportTemplate(ctx)

	return data, d.operationError(err)
}
