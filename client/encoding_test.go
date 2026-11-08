package client_test

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"slices"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestExtendedLengthCommandWire(t *testing.T) {
	certificate := bytes.Repeat([]byte{0x5a}, 300)
	for _, tt := range []struct {
		name     string
		command  []byte
		response []byte
		call     func(*client.Client) ([]byte, error)
	}{
		{
			name:     "get data",
			command:  []byte{0, 0xca, 0x7f, 0x21, 0, 0, 0},
			response: certificate,
			call: func(c *client.Client) ([]byte, error) {
				return c.GetData(t.Context(), protocol.CardholderCertificateObject)
			},
		},
		{
			name:    "put data",
			command: slices.Concat([]byte{0, 0xda, 0x7f, 0x21, 0, 1, 0x2c}, certificate),
			call: func(c *client.Client) ([]byte, error) {
				return nil, c.PutData(t.Context(), protocol.CardholderCertificateObject, certificate)
			},
		},
		{
			name:    "verify",
			command: []byte{0, 0x20, 0, 0x81, 0, 0, 6, '1', '2', '3', '4', '5', '6'},
			call: func(c *client.Client) ([]byte, error) {
				return nil, c.Verify(t.Context(), protocol.PW1Sign, []byte("123456"))
			},
		},
		{
			name:    "select data",
			command: []byte{0, 0xa5, 2, 4, 0, 0, 6, 0x60, 4, 0x5c, 2, 0x7f, 0x21, 0, 0},
			call: func(c *client.Client) ([]byte, error) {
				return nil, c.SelectData(t.Context(), protocol.CardholderCertificateObject, 2)
			},
		},
		{
			name:     "signature",
			command:  []byte{0, 0x2a, 0x9e, 0x9a, 0, 0, 3, 1, 2, 3, 0, 0},
			response: []byte{4, 5},
			call: func(c *client.Client) ([]byte, error) {
				return c.ComputeDigitalSignature(t.Context(), []byte{1, 2, 3})
			},
		},
		{
			name:     "authenticate",
			command:  []byte{0, 0x88, 0, 0, 0, 0, 3, 1, 2, 3, 0, 0},
			response: []byte{4, 5},
			call: func(c *client.Client) ([]byte, error) {
				return c.InternalAuthenticate(t.Context(), []byte{1, 2, 3})
			},
		},
		{
			name:     "decipher",
			command:  []byte{0, 0x2a, 0x80, 0x86, 0, 0, 3, 0, 2, 3, 0, 0},
			response: []byte{4, 5},
			call: func(c *client.Client) ([]byte, error) {
				return c.Decipher(t.Context(), []byte{0, 2, 3})
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newExtendedClient(t, step{
				command:  tt.command,
				response: iso7816.Response{Status: 0x9000, Data: tt.response},
			})

			got, err := tt.call(c)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got, tt.response) {
				t.Errorf("result = %x, want %x", got, tt.response)
			}
		})
	}
}

func TestExtendedLengthPublicKeyWire(t *testing.T) {
	scalar := [32]byte{31: 1}

	key, err := ecdh.P256().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatal(err)
	}

	point := key.PublicKey().Bytes()
	response := slices.Concat([]byte{0x7f, 0x49, 67, 0x86, 65}, point)

	for _, tt := range []struct {
		name    string
		command []byte
		call    func(*client.Client) (crypto.PublicKey, error)
	}{
		{
			name:    "read",
			command: []byte{0, 0x47, 0x81, 0, 0, 0, 2, 0xb6, 0, 0, 0},
			call: func(c *client.Client) (crypto.PublicKey, error) {
				return c.ReadPublicKey(t.Context(), protocol.DigitalSignatureTemplateTag)
			},
		},
		{
			name:    "generate",
			command: []byte{0, 0x47, 0x80, 0, 0, 0, 2, 0xb6, 0, 0, 0},
			call: func(c *client.Client) (crypto.PublicKey, error) {
				return c.GenerateAsymmetricKeyPair(t.Context(), protocol.DigitalSignatureTemplateTag)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newExtendedClient(t,
				step{command: []byte{0, 0xca, 0, 0x6e, 0, 0, 0}, response: iso7816.Response{Status: 0x9000, Data: signatureApplication}},
				step{command: tt.command, response: iso7816.Response{Status: 0x9000, Data: response}},
			)

			public, err := tt.call(c)
			if err != nil {
				t.Fatal(err)
			}

			got, ok := public.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("public key type = %T", public)
			}

			encoded, err := got.Bytes()
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(encoded, point) {
				t.Errorf("public key = %v", public)
			}
		})
	}
}

func TestChallengeEncodingKeepsRequestedLength(t *testing.T) {
	for _, tt := range []struct {
		name     string
		length   uint32
		extended bool
		command  []byte
	}{
		{name: "default/4", length: 4, command: []byte{0, 0x84, 0, 0, 4}},
		{name: "default/255", length: 255, command: []byte{0, 0x84, 0, 0, 0xff}},
		{name: "default/256", length: 256, command: []byte{0, 0x84, 0, 0, 0, 1, 0}},
		{name: "default/257", length: 257, command: []byte{0, 0x84, 0, 0, 0, 1, 1}},
		{name: "extended/4", length: 4, extended: true, command: []byte{0, 0x84, 0, 0, 0, 0, 4}},
		{name: "extended/255", length: 255, extended: true, command: []byte{0, 0x84, 0, 0, 0, 0, 0xff}},
		{name: "extended/256", length: 256, extended: true, command: []byte{0, 0x84, 0, 0, 0, 1, 0}},
		{name: "extended/257", length: 257, extended: true, command: []byte{0, 0x84, 0, 0, 0, 1, 1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			challenge := bytes.Repeat([]byte{0x5a}, int(tt.length))
			s := step{
				command:  tt.command,
				response: iso7816.Response{Status: 0x9000, Data: challenge},
			}

			var c *client.Client
			if tt.extended {
				c = newExtendedClient(t, s)
			} else {
				c = newClient(t, s)
			}

			got, err := c.GetChallenge(t.Context(), tt.length)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got, challenge) {
				t.Errorf("challenge = %x, want %x", got, challenge)
			}
		})
	}
}

func TestExtendedLengthSelectKeepsShortEncoding(t *testing.T) {
	c := newExtendedClient(t, step{
		command:  []byte{0, 0xa4, 4, 0, 6, 0xd2, 0x76, 0, 1, 0x24, 1, 0},
		response: iso7816.Response{Status: 0x9000},
	})

	if err := c.Select(t.Context()); err != nil {
		t.Fatal(err)
	}
}
