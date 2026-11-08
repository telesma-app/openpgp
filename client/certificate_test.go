package client_test

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport"
)

func TestCardholderCertificateWire(t *testing.T) {
	certificate := []byte{0x30, 3, 1, 2, 3}

	for _, tt := range []struct {
		name       string
		key        protocol.ControlReferenceTemplateTag
		occurrence byte
	}{
		{name: "authentication", key: protocol.AuthenticationTemplateTag, occurrence: 0},
		{name: "decryption", key: protocol.ConfidentialityTemplateTag, occurrence: 1},
		{name: "signature", key: protocol.DigitalSignatureTemplateTag, occurrence: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			selectCommand := []byte{0, 0xa5, tt.occurrence, 4, 6, 0x60, 4, 0x5c, 2, 0x7f, 0x21, 0}
			c := newClient(t,
				step{command: selectCommand, response: iso7816.Response{Status: 0x9000}},
				step{command: []byte{0, 0xca, 0x7f, 0x21, 0}, response: iso7816.Response{Status: 0x9000, Data: certificate}},
				step{command: selectCommand, response: iso7816.Response{Status: 0x9000}},
				step{command: []byte{0, 0xda, 0x7f, 0x21, 5, 0x30, 3, 1, 2, 3}, response: iso7816.Response{Status: 0x9000}},
			)

			got, err := c.GetCardholderCertificate(t.Context(), tt.key)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got, certificate) {
				t.Errorf("certificate = %x, want %x", got, certificate)
			}

			if err := c.PutCardholderCertificate(t.Context(), tt.key, certificate); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCardholderCertificateSelectionFailureStopsOperation(t *testing.T) {
	for _, tt := range []struct {
		name string
		call func(*client.Client) error
	}{
		{
			name: "read",
			call: func(c *client.Client) error {
				_, err := c.GetCardholderCertificate(t.Context(), protocol.AuthenticationTemplateTag)
				return err
			},
		},
		{
			name: "write",
			call: func(c *client.Client) error {
				return c.PutCardholderCertificate(t.Context(), protocol.AuthenticationTemplateTag, []byte{1, 2, 3})
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newClient(t, step{
				command:  []byte{0, 0xa5, 0, 4, 6, 0x60, 4, 0x5c, 2, 0x7f, 0x21, 0},
				response: iso7816.Response{Status: 0x6a88},
			})

			err := tt.call(c)

			var apduError *iso7816.APDUError
			if !errors.As(err, &apduError) || apduError.StatusWord() != 0x6a88 {
				t.Fatalf("selection error = %v, want APDU error 6a88", err)
			}
		})
	}
}

func TestCardholderCertificateDataFailurePreservesError(t *testing.T) {
	for _, operation := range []struct {
		name    string
		command []byte
		call    func(*client.Client) error
	}{
		{
			name:    "read",
			command: []byte{0, 0xca, 0x7f, 0x21, 0},
			call: func(c *client.Client) error {
				_, err := c.GetCardholderCertificate(t.Context(), protocol.ConfidentialityTemplateTag)
				return err
			},
		},
		{
			name:    "write",
			command: []byte{0, 0xda, 0x7f, 0x21, 3, 1, 2, 3},
			call: func(c *client.Client) error {
				return c.PutCardholderCertificate(t.Context(), protocol.ConfidentialityTemplateTag, []byte{1, 2, 3})
			},
		},
	} {
		for _, failure := range []struct {
			name     string
			response iso7816.Response
			err      error
		}{
			{name: "APDU", response: iso7816.Response{Status: 0x6982}},
			{name: "transport", err: &transport.DeviceInvalidatedError{Err: io.ErrUnexpectedEOF}},
		} {
			t.Run(operation.name+"/"+failure.name, func(t *testing.T) {
				c := newClient(t,
					step{command: []byte{0, 0xa5, 1, 4, 6, 0x60, 4, 0x5c, 2, 0x7f, 0x21, 0}, response: iso7816.Response{Status: 0x9000}},
					step{command: operation.command, response: failure.response, err: failure.err},
				)

				err := operation.call(c)

				if failure.err != nil {
					var invalidated *transport.DeviceInvalidatedError
					if !errors.As(err, &invalidated) || !errors.Is(err, io.ErrUnexpectedEOF) {
						t.Fatalf("data error = %v, want invalidation with original cause", err)
					}
				} else {
					var apduError *iso7816.APDUError
					if !errors.As(err, &apduError) || apduError.StatusWord() != 0x6982 {
						t.Fatalf("data error = %v, want APDU error 6982", err)
					}
				}
			})
		}
	}
}

func TestEmptyCardholderCertificateIsDistinctFromUnavailableObject(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status iso7816.StatusWord
	}{
		{name: "empty", status: 0x9000},
		{name: "unavailable", status: 0x6a88},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newClient(t,
				step{command: []byte{0, 0xa5, 2, 4, 6, 0x60, 4, 0x5c, 2, 0x7f, 0x21, 0}, response: iso7816.Response{Status: 0x9000}},
				step{command: []byte{0, 0xca, 0x7f, 0x21, 0}, response: iso7816.Response{Status: tt.status}},
			)

			got, err := c.GetCardholderCertificate(t.Context(), protocol.DigitalSignatureTemplateTag)

			if tt.status == 0x9000 {
				if err != nil || len(got) != 0 {
					t.Fatalf("empty certificate = %x, %v", got, err)
				}
			} else {
				var apduError *iso7816.APDUError
				if !errors.As(err, &apduError) || apduError.StatusWord() != 0x6a88 {
					t.Fatalf("unavailable certificate error = %v, want APDU error 6a88", err)
				}
			}
		})
	}
}

func TestEmptyPutCardholderCertificateDeletesContents(t *testing.T) {
	for _, tt := range []struct {
		name string
		data []byte
	}{
		{name: "nil"},
		{name: "empty", data: []byte{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newClient(t,
				step{command: []byte{0, 0xa5, 0, 4, 6, 0x60, 4, 0x5c, 2, 0x7f, 0x21, 0}, response: iso7816.Response{Status: 0x9000}},
				step{command: []byte{0, 0xda, 0x7f, 0x21}, response: iso7816.Response{Status: 0x9000}},
			)

			if err := c.PutCardholderCertificate(t.Context(), protocol.AuthenticationTemplateTag, tt.data); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCardholderCertificateExtendedWire(t *testing.T) {
	certificate := bytes.Repeat([]byte{0x5a}, 300)
	selectCommand := []byte{0, 0xa5, 1, 4, 0, 0, 6, 0x60, 4, 0x5c, 2, 0x7f, 0x21, 0, 0}
	c := newExtendedClient(t,
		step{command: selectCommand, response: iso7816.Response{Status: 0x9000}},
		step{command: []byte{0, 0xca, 0x7f, 0x21, 0, 0, 0}, response: iso7816.Response{Status: 0x9000, Data: certificate}},
		step{command: selectCommand, response: iso7816.Response{Status: 0x9000}},
		step{command: slices.Concat([]byte{0, 0xda, 0x7f, 0x21, 0, 1, 0x2c}, certificate), response: iso7816.Response{Status: 0x9000}},
	)

	got, err := c.GetCardholderCertificate(t.Context(), protocol.ConfidentialityTemplateTag)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, certificate) {
		t.Errorf("certificate = %x, want %x", got, certificate)
	}

	if err := c.PutCardholderCertificate(t.Context(), protocol.ConfidentialityTemplateTag, certificate); err != nil {
		t.Fatal(err)
	}
}
