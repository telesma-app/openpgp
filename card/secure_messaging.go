package card

import (
	"context"
	"errors"

	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport"
	"github.com/telesma-app/openpgp/transport/sm"
)

// OpenSecureMessaging reads the selected card's capabilities and opens a
// static-key AES secure messaging session. OpenPGP must have its default
// SIG/DEC/AUT bindings, as after SELECT. Keys must already be provisioned.
// The caller serializes initialization and stops using connection directly on
// success. On any error, including invalidation, the caller retains ownership.
// Options configure discovery and subsequent card commands.
func OpenSecureMessaging(
	ctx context.Context,
	connection transport.Device,
	parameters sm.Parameters,
	options ...client.Option,
) (*Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c := client.NewClient(connection, options...)

	application, err := c.GetApplicationRelatedData(ctx)
	if err != nil {
		return nil, err
	}

	capabilities := application.ExtendedCapabilities
	if capabilities == nil {
		data, err := c.GetData(ctx, protocol.ExtendedCapabilitiesObject)
		if err != nil {
			return nil, err
		}

		value, err := protocol.ParseExtendedCapabilities(data)
		if err != nil {
			return nil, err
		}

		capabilities = &value
	}

	algorithm := protocol.SecureMessagingAES128
	if len(parameters.Keys.ENC) == 32 {
		algorithm = protocol.SecureMessagingAES256
	}

	if !capabilities.SecureMessaging || capabilities.SecureMessagingAlgorithm != algorithm {
		return nil, errors.New("openpgp: card does not advertise the requested static-key AES algorithm")
	}

	secure, err := sm.New(connection, parameters)
	if err != nil {
		return nil, err
	}

	return New(secure, options...), nil
}
