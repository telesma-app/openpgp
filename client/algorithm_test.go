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
)

func TestGetAlgorithmAttributes(t *testing.T) {
	application := []byte{
		0x4f, 0x10, 0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 6, 0, 0, 0, 1, 0, 0,
		0x73, 0x18,
		0xc1, 6, 1, 8, 0, 0, 0x20, 0,
		0xc2, 6, 1, 0x0c, 0, 0, 0x20, 1,
		0xc3, 6, 1, 0x10, 0, 0, 0x20, 2,
	}

	for _, test := range []struct {
		name   string
		object protocol.Object
		bits   uint16
		format protocol.ImportFormat
		extend bool
		steps  []step
	}{
		{
			name: "SIG in 6E", object: protocol.SignatureAlgorithmAttributesObject, bits: 2048,
			steps: []step{{command: []byte{0, 0xca, 0, 0x6e, 0}, response: iso7816.Response{Status: 0x9000, Data: application}}},
		},
		{
			name: "DEC in 6E", object: protocol.DecryptionAlgorithmAttributesObject, bits: 3072, format: protocol.ImportFormatStandardWithModulus,
			steps: []step{{command: []byte{0, 0xca, 0, 0x6e, 0}, response: iso7816.Response{Status: 0x9000, Data: application}}},
		},
		{
			name: "AUT in extended 6E", object: protocol.AuthenticationAlgorithmAttributesObject, bits: 4096, format: protocol.ImportFormatCRT, extend: true,
			steps: []step{{command: []byte{0, 0xca, 0, 0x6e, 0, 0, 0}, response: iso7816.Response{Status: 0x9000, Data: application}}},
		},
		{
			name: "DEC omitted from 6E", object: protocol.DecryptionAlgorithmAttributesObject, bits: 3072, format: protocol.ImportFormatCRTWithModulus,
			steps: []step{
				{command: []byte{0, 0xca, 0, 0x6e, 0}, response: iso7816.Response{Status: 0x9000, Data: signatureApplication}},
				{command: []byte{0, 0xca, 0, 0xc2, 0}, response: iso7816.Response{Status: 0x9000, Data: []byte{1, 0x0c, 0, 0, 0x20, 3}}},
			},
		},
		{
			name: "attestation direct", object: protocol.AttestationAlgorithmAttributesObject, bits: 2048,
			steps: []step{{command: []byte{0, 0xca, 0, 0xda, 0}, response: iso7816.Response{Status: 0x9000, Data: []byte{1, 8, 0, 0, 0x20, 0}}}},
		},
		{
			name: "proprietary direct", object: 0x0110, bits: 4096,
			steps: []step{{command: []byte{0, 0xca, 1, 0x10, 0}, response: iso7816.Response{Status: 0x9000, Data: []byte{1, 0x10, 0, 0, 0x20, 0}}}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var c *client.Client
			if test.extend {
				c = newExtendedClient(t, test.steps...)
			} else {
				c = newClient(t, test.steps...)
			}

			got, err := c.GetAlgorithmAttributes(t.Context(), test.object)
			if err != nil {
				t.Fatal(err)
			}

			if got.Algorithm != protocol.RSA || got.ModulusBits != test.bits || got.ExponentBits != 32 || got.ImportFormat != test.format {
				t.Errorf("attributes = %+v, want RSA %d-bit format %d", got, test.bits, test.format)
			}
		})
	}
}

func TestPutAlgorithmAttributesWire(t *testing.T) {
	for _, test := range []struct {
		name       string
		object     protocol.Object
		attributes protocol.AlgorithmAttributes
		extend     bool
		wire       []byte
	}{
		{
			name: "RSA short", object: protocol.SignatureAlgorithmAttributesObject,
			attributes: protocol.AlgorithmAttributes{Algorithm: protocol.RSA, ModulusBits: 2048, ExponentBits: 32},
			wire:       []byte{0, 0xda, 0, 0xc1, 6, 1, 8, 0, 0, 0x20, 0},
		},
		{
			name: "unsupported local curve extended", object: protocol.DecryptionAlgorithmAttributesObject, extend: true,
			attributes: protocol.AlgorithmAttributes{Algorithm: protocol.ECDH, CurveOID: []byte{0x2b, 6, 1}},
			wire:       []byte{0, 0xda, 0, 0xc2, 0, 0, 4, 0x12, 0x2b, 6, 1},
		},
		{
			name: "unknown algorithm proprietary object", object: 0x0110,
			attributes: protocol.AlgorithmAttributes{Algorithm: 0x7f, Raw: []byte{0x7f, 0x11, 0x22}},
			wire:       []byte{0, 0xda, 1, 0x10, 3, 0x7f, 0x11, 0x22},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var c *client.Client

			request := step{command: test.wire, response: iso7816.Response{Status: 0x9000}}
			if test.extend {
				c = newExtendedClient(t, request)
			} else {
				c = newClient(t, request)
			}

			if err := c.PutAlgorithmAttributes(t.Context(), test.object, test.attributes); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGetAlgorithmInformationWire(t *testing.T) {
	data := []byte{
		0xfa, 0x15,
		0xc1, 6, 1, 8, 0, 0, 0x20, 0,
		0xc1, 6, 1, 0x0c, 0, 0, 0x20, 3,
		0xda, 3, 0x7f, 0x11, 0x22,
	}

	for _, test := range []struct {
		name string
		new  func(*testing.T, ...step) *client.Client
		wire []byte
	}{
		{name: "short", new: newClient, wire: []byte{0, 0xca, 0, 0xfa, 0}},
		{name: "extended", new: newExtendedClient, wire: []byte{0, 0xca, 0, 0xfa, 0, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := test.new(t, step{command: test.wire, response: iso7816.Response{Status: 0x9000, Data: data}})

			got, err := c.GetAlgorithmInformation(t.Context())
			if err != nil {
				t.Fatal(err)
			}

			if len(got) != 3 || got[0].Object != protocol.SignatureAlgorithmAttributesObject ||
				got[1].Object != protocol.SignatureAlgorithmAttributesObject || got[2].Object != protocol.AttestationAlgorithmAttributesObject {
				t.Fatalf("algorithm entries = %+v, want C1, C1, DA", got)
			}

			if got[0].Attributes.ModulusBits != 2048 || got[1].Attributes.ModulusBits != 3072 ||
				got[2].Attributes.Algorithm != 0x7f || !bytes.Equal(got[2].Attributes.Raw, []byte{0x7f, 0x11, 0x22}) {
				t.Errorf("algorithm values = %+v", got)
			}
		})
	}
}

func TestAlgorithmAccessErrorsStopWithoutFurtherCommands(t *testing.T) {
	for _, operation := range []struct {
		name string
		wire []byte
		call func(*client.Client) error
	}{
		{
			name: "information", wire: []byte{0, 0xca, 0, 0xfa, 0},
			call: func(c *client.Client) error { _, err := c.GetAlgorithmInformation(t.Context()); return err },
		},
		{
			name: "attributes in 6E", wire: []byte{0, 0xca, 0, 0x6e, 0},
			call: func(c *client.Client) error {
				_, err := c.GetAlgorithmAttributes(t.Context(), protocol.SignatureAlgorithmAttributesObject)
				return err
			},
		},
		{
			name: "put", wire: []byte{0, 0xda, 0, 0xc1, 6, 1, 8, 0, 0, 0x20, 0},
			call: func(c *client.Client) error {
				return c.PutAlgorithmAttributes(t.Context(), protocol.SignatureAlgorithmAttributesObject, protocol.AlgorithmAttributes{Algorithm: protocol.RSA, ModulusBits: 2048, ExponentBits: 32})
			},
		},
	} {
		for _, failure := range []struct {
			name string
			err  error
		}{
			{name: "APDU"},
			{name: "transport", err: io.ErrUnexpectedEOF},
		} {
			t.Run(operation.name+"/"+failure.name, func(t *testing.T) {
				c := newClient(t, step{command: operation.wire, response: iso7816.Response{Status: 0x6982}, err: failure.err})

				err := operation.call(c)

				if failure.err != nil {
					if !errors.Is(err, failure.err) {
						t.Errorf("error = %v, want %v", err, failure.err)
					}
				} else {
					var apdu *iso7816.APDUError
					if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6982 {
						t.Errorf("error = %v, want APDU error 6982", err)
					}
				}
			})
		}
	}
}

func TestAlgorithmInformationSelectionCanBeWrittenDirectly(t *testing.T) {
	data := []byte{0xdf, 0x20, 3, 0x7f, 0x11, 0x22}
	c := newClient(t,
		step{command: []byte{0, 0xca, 0, 0xfa, 0}, response: iso7816.Response{Status: 0x9000, Data: data}},
		step{command: []byte{0, 0xda, 0xdf, 0x20, 3, 0x7f, 0x11, 0x22}, response: iso7816.Response{Status: 0x9000}},
	)
	before := slices.Clone(data)

	entries, err := c.GetAlgorithmInformation(t.Context())
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %+v, %v", entries, err)
	}

	if err := c.PutAlgorithmAttributes(t.Context(), entries[0].Object, entries[0].Attributes); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, before) {
		t.Errorf("borrowed information changed to %x, want %x", data, before)
	}
}
