package card_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/hex"
	"testing"

	"github.com/telesma-app/openpgp/card"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestIntegrationControlReferenceTemplateCommandEncoding(t *testing.T) {
	// SEC 2 secp256r1 generator, encoded as the uncompressed public point.
	point, err := hex.DecodeString("04" +
		"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
		"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
	if err != nil {
		t.Fatal(err)
	}

	attributes := protocol.AlgorithmAttributes{
		Algorithm: protocol.ECDSA,
		CurveOID:  []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
	}

	for _, operation := range []struct {
		name string
		p1   byte
		call func(*card.Device, context.Context, protocol.ControlReferenceTemplate, protocol.AlgorithmAttributes) (crypto.PublicKey, error)
	}{
		{name: "read", p1: 0x81, call: (*card.Device).ReadPublicKeyWithTemplate},
		{
			name: "generate", p1: 0x80,
			call: func(d *card.Device, ctx context.Context, template protocol.ControlReferenceTemplate, attributes protocol.AlgorithmAttributes) (crypto.PublicKey, error) {
				return d.GenerateAsymmetricKeyPairWithTemplate(ctx, template, attributes, nil)
			},
		},
	} {
		t.Run(operation.name, func(t *testing.T) {
			for _, key := range []struct {
				name       string
				number     protocol.KeyReference
				wireNumber byte
			}{
				{name: "standard key number", number: protocol.SignatureKeyReference, wireNumber: 0x01},
				{name: "additional key number", number: protocol.AttestationKeyReference, wireNumber: 0x81},
			} {
				t.Run(key.name, func(t *testing.T) {
					for _, mode := range []struct {
						name     string
						extended bool
					}{
						{name: "short APDU"},
						{name: "extended APDU", extended: true},
					} {
						t.Run(mode.name, func(t *testing.T) {
							request := []byte{0x00, 0x47, operation.p1, 0x00, 0x05, 0xb6, 0x03, 0x84, 0x01, key.wireNumber, 0x00}

							var options []client.Option
							if mode.extended {
								options = []client.Option{client.WithExtendedLength()}
								request = []byte{0x00, 0x47, operation.p1, 0x00, 0x00, 0x00, 0x05, 0xb6, 0x03, 0x84, 0x01, key.wireNumber, 0x00, 0x00}
							}

							response := append([]byte{0x7f, 0x49, 0x43, 0x86, 0x41}, point...)
							response = append(response, 0x90, 0x00)
							// The peer permits only SELECT and the key command: supplied
							// attributes must not trigger metadata reads or configuration.
							device := newEncodingDevice(t, options, encodingExchange{request: request, response: response})
							template := protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag, KeyReference: key.number}

							got, err := operation.call(device, t.Context(), template, attributes)
							if err != nil {
								t.Fatal(err)
							}

							public, ok := got.(*ecdsa.PublicKey)
							if !ok {
								t.Fatalf("public key type = %T, want ECDSA", got)
							}

							encoded, err := public.Bytes()
							if err != nil {
								t.Fatal(err)
							}

							if !bytes.Equal(encoded, point) {
								t.Errorf("public point = %x, want %x", encoded, point)
							}
						})
					}
				})
			}
		})
	}
}
