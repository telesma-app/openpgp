package client_test

import (
	"errors"
	"io"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport"
)

func TestManageSecurityEnvironmentWire(t *testing.T) {
	for _, tt := range []struct {
		name      string
		extended  bool
		operation protocol.ControlReferenceTemplateTag
		key       protocol.KeyReference
		command   []byte
	}{
		{
			name:      "short authentication uses decryption key",
			operation: protocol.AuthenticationTemplateTag,
			key:       protocol.DecryptionKeyReference,
			command:   []byte{0, 0x22, 0x41, 0xa4, 3, 0x83, 1, 2},
		},
		{
			name:      "short decryption uses authentication key",
			operation: protocol.ConfidentialityTemplateTag,
			key:       protocol.AuthenticationKeyReference,
			command:   []byte{0, 0x22, 0x41, 0xb8, 3, 0x83, 1, 3},
		},
		{
			name:      "short authentication default",
			operation: protocol.AuthenticationTemplateTag,
			key:       protocol.AuthenticationKeyReference,
			command:   []byte{0, 0x22, 0x41, 0xa4, 3, 0x83, 1, 3},
		},
		{
			name:      "short decryption default",
			operation: protocol.ConfidentialityTemplateTag,
			key:       protocol.DecryptionKeyReference,
			command:   []byte{0, 0x22, 0x41, 0xb8, 3, 0x83, 1, 2},
		},
		{
			name:      "extended authentication uses decryption key",
			extended:  true,
			operation: protocol.AuthenticationTemplateTag,
			key:       protocol.DecryptionKeyReference,
			command:   []byte{0, 0x22, 0x41, 0xa4, 0, 0, 3, 0x83, 1, 2},
		},
		{
			name:      "extended decryption uses authentication key",
			extended:  true,
			operation: protocol.ConfidentialityTemplateTag,
			key:       protocol.AuthenticationKeyReference,
			command:   []byte{0, 0x22, 0x41, 0xb8, 0, 0, 3, 0x83, 1, 3},
		},
		{
			name:      "extended authentication default",
			extended:  true,
			operation: protocol.AuthenticationTemplateTag,
			key:       protocol.AuthenticationKeyReference,
			command:   []byte{0, 0x22, 0x41, 0xa4, 0, 0, 3, 0x83, 1, 3},
		},
		{
			name:      "extended decryption default",
			extended:  true,
			operation: protocol.ConfidentialityTemplateTag,
			key:       protocol.DecryptionKeyReference,
			command:   []byte{0, 0x22, 0x41, 0xb8, 0, 0, 3, 0x83, 1, 2},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := step{command: tt.command, response: iso7816.Response{Status: 0x9000}}

			var c *client.Client
			if tt.extended {
				c = newExtendedClient(t, s)
			} else {
				c = newClient(t, s)
			}

			if err := c.ManageSecurityEnvironment(t.Context(), tt.operation, tt.key); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestManageSecurityEnvironmentFailureDoesNotRetry(t *testing.T) {
	for _, tt := range []struct {
		name     string
		response iso7816.Response
		err      error
	}{
		{name: "APDU", response: iso7816.Response{Status: 0x6a80}},
		{name: "transport", err: &transport.DeviceInvalidatedError{Err: io.ErrUnexpectedEOF}},
		{name: "unexpected response data", response: iso7816.Response{Status: 0x9000, Data: []byte{1}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newClient(t, step{
				command:  []byte{0, 0x22, 0x41, 0xa4, 3, 0x83, 1, 2},
				response: tt.response,
				err:      tt.err,
			})

			err := c.ManageSecurityEnvironment(t.Context(), protocol.AuthenticationTemplateTag, protocol.DecryptionKeyReference)

			switch {
			case tt.err != nil:
				var invalidated *transport.DeviceInvalidatedError
				if !errors.As(err, &invalidated) || !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("error = %v, want invalidation with original cause", err)
				}
			case tt.response.Status != 0x9000:
				var apduError *iso7816.APDUError
				if !errors.As(err, &apduError) || apduError.StatusWord() != 0x6a80 {
					t.Fatalf("error = %v, want APDU error 6a80", err)
				}
			default:
				if !errors.Is(err, protocol.ErrInvalidResponse) {
					t.Fatalf("error = %v, want invalid response", err)
				}
			}
		})
	}
}
