package client

import (
	"context"

	"github.com/telesma-app/openpgp/protocol"
)

// GetUserInteractionFlag reads a User Interaction Flag object (Sec. 4.4.3.6).
// D6-D8 are read from Application Related Data, or individually when omitted
// there (Sec. 4.4.3.1). Other objects are read directly. Unknown values are retained.
func (c *Client) GetUserInteractionFlag(ctx context.Context, object protocol.Object) (protocol.UserInteractionFlag, error) {
	switch object {
	case protocol.SignatureUIFObject, protocol.DecryptionUIFObject, protocol.AuthenticationUIFObject:
		application, err := c.GetApplicationRelatedData(ctx)
		if err != nil {
			return protocol.UserInteractionFlag{}, err
		}

		var flag *protocol.UserInteractionFlag

		switch object {
		case protocol.SignatureUIFObject:
			flag = application.SignatureUIF
		case protocol.DecryptionUIFObject:
			flag = application.DecryptionUIF
		case protocol.AuthenticationUIFObject:
			flag = application.AuthenticationUIF
		}

		if flag != nil {
			return *flag, nil
		}
	}

	data, err := c.GetData(ctx, object)
	if err != nil {
		return protocol.UserInteractionFlag{}, err
	}

	return protocol.ParseUserInteractionFlag(data)
}

// PutUserInteractionFlag writes the supplied State and Features after PW3
// verification (Sec. 4.4.3.6). On cards supporting UIFPermanentlyEnabled, that
// state prevents further changes until a factory reset.
func (c *Client) PutUserInteractionFlag(ctx context.Context, object protocol.Object, flag protocol.UserInteractionFlag) error {
	return c.PutData(ctx, object, protocol.EncodeUserInteractionFlag(flag))
}
