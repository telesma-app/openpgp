package client_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestControlReferenceTemplateCommandWire(t *testing.T) {
	attributes, response, point := controlReferenceTemplateP256Fixture(t)

	for _, operation := range []struct {
		name string
		p1   byte
		call func(*client.Client, context.Context, protocol.ControlReferenceTemplate, protocol.AlgorithmAttributes) (crypto.PublicKey, error)
	}{
		{name: "read", p1: 0x81, call: (*client.Client).ReadPublicKeyWithTemplate},
		{name: "generate", p1: 0x80, call: (*client.Client).GenerateAsymmetricKeyPairWithTemplate},
	} {
		t.Run(operation.name, func(t *testing.T) {
			for _, test := range []struct {
				name     string
				template protocol.ControlReferenceTemplate
				extended bool
				command  []byte
			}{
				{
					name:     "short CRT short APDU",
					template: protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag},
					command:  []byte{0, 0x47, 0x81, 0, 2, 0xb6, 0, 0},
				},
				{
					name:     "extended SIG CRT short APDU",
					template: protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag, KeyReference: protocol.SignatureKeyReference},
					command:  []byte{0, 0x47, 0x81, 0, 5, 0xb6, 3, 0x84, 1, 1, 0},
				},
				{
					name:     "extended DEC CRT short APDU",
					template: protocol.ControlReferenceTemplate{Tag: protocol.ConfidentialityTemplateTag, KeyReference: protocol.DecryptionKeyReference},
					command:  []byte{0, 0x47, 0x81, 0, 5, 0xb8, 3, 0x84, 1, 2, 0},
				},
				{
					name:     "extended AUT CRT short APDU",
					template: protocol.ControlReferenceTemplate{Tag: protocol.AuthenticationTemplateTag, KeyReference: protocol.AuthenticationKeyReference},
					command:  []byte{0, 0x47, 0x81, 0, 5, 0xa4, 3, 0x84, 1, 3, 0},
				},
				{
					name:     "additional CRT short APDU",
					template: protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag, KeyReference: protocol.AttestationKeyReference},
					command:  []byte{0, 0x47, 0x81, 0, 5, 0xb6, 3, 0x84, 1, 0x81, 0},
				},
				{
					name:     "short CRT extended APDU",
					template: protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag},
					extended: true,
					command:  []byte{0, 0x47, 0x81, 0, 0, 0, 2, 0xb6, 0, 0, 0},
				},
				{
					name:     "additional CRT extended APDU",
					template: protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag, KeyReference: protocol.AttestationKeyReference},
					extended: true,
					command:  []byte{0, 0x47, 0x81, 0, 0, 0, 5, 0xb6, 3, 0x84, 1, 0x81, 0, 0},
				},
			} {
				t.Run(test.name, func(t *testing.T) {
					command := slices.Clone(test.command)
					command[2] = operation.p1
					request := step{command: command, response: iso7816.Response{Status: 0x9000, Data: response}}

					var c *client.Client
					if test.extended {
						c = newExtendedClient(t, request)
					} else {
						c = newClient(t, request)
					}

					public, err := operation.call(c, t.Context(), test.template, attributes)
					if err != nil {
						t.Fatal(err)
					}

					key, ok := public.(*ecdsa.PublicKey)
					if !ok {
						t.Fatalf("public key type = %T, want ECDSA", public)
					}

					encoded, err := key.Bytes()
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
}

func TestReadAdditionalKeyUsesExplicitAttributesWithoutLookup(t *testing.T) {
	scalar := [48]byte{47: 2}

	key, err := ecdh.P384().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatal(err)
	}

	point := key.PublicKey().Bytes()
	response := slices.Concat([]byte{0x7f, 0x49, 99, 0x86, 97}, point)
	c := newClient(t, step{
		command:  []byte{0, 0x47, 0x81, 0, 5, 0xb6, 3, 0x84, 1, 0x81, 0},
		response: iso7816.Response{Status: 0x9000, Data: response},
	})

	// The standard SIG fixture uses P-256. This additional key instead uses
	// the caller's P-384 attributes, with no metadata reads or writes.
	public, err := c.ReadPublicKeyWithTemplate(t.Context(), protocol.ControlReferenceTemplate{
		Tag: protocol.DigitalSignatureTemplateTag, KeyReference: protocol.AttestationKeyReference,
	}, protocol.AlgorithmAttributes{
		Algorithm: protocol.ECDSA, CurveOID: []byte{0x2b, 0x81, 0x04, 0x00, 0x22},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, ok := public.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want ECDSA", public)
	}

	encoded, err := got.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(encoded, point) || got.Params().N.BitLen() != 384 {
		t.Errorf("public point = %x, want P-384 point %x", encoded, point)
	}
}

func TestTemplateGenerationChecksDecoderSupportBeforeIO(t *testing.T) {
	for _, test := range []struct {
		name       string
		attributes protocol.AlgorithmAttributes
	}{
		{name: "unknown algorithm", attributes: protocol.AlgorithmAttributes{Algorithm: 99}},
		{
			name: "unsupported ECDSA curve",
			attributes: protocol.AlgorithmAttributes{
				Algorithm: protocol.ECDSA, CurveOID: []byte{0x2b, 0x65, 0x6e},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := newClient(t)

			public, err := c.GenerateAsymmetricKeyPairWithTemplate(t.Context(), protocol.ControlReferenceTemplate{
				Tag: protocol.DigitalSignatureTemplateTag, KeyReference: protocol.AttestationKeyReference,
			}, test.attributes)
			if public != nil || !errors.Is(err, protocol.ErrUnsupportedAlgorithm) {
				t.Fatalf("generation = %v, %v; want unsupported algorithm before I/O", public, err)
			}
		})
	}
}

func TestTemplateGenerationAcknowledgementPreservesTarget(t *testing.T) {
	attributes, validResponse, _ := controlReferenceTemplateP256Fixture(t)

	for _, test := range []struct {
		name       string
		template   protocol.ControlReferenceTemplate
		attributes protocol.AlgorithmAttributes
		command    []byte
		response   []byte
		crt        string
	}{
		{
			name: "short CRT malformed response",
			template: protocol.ControlReferenceTemplate{
				Tag: protocol.DigitalSignatureTemplateTag,
			},
			attributes: attributes,
			command:    []byte{0, 0x47, 0x80, 0, 2, 0xb6, 0, 0},
			response:   []byte{0x7f},
			crt:        "b600",
		},
		{
			name: "explicit standard CRT malformed response",
			template: protocol.ControlReferenceTemplate{
				Tag: protocol.DigitalSignatureTemplateTag, KeyReference: protocol.SignatureKeyReference,
			},
			attributes: attributes,
			command:    []byte{0, 0x47, 0x80, 0, 5, 0xb6, 3, 0x84, 1, 1, 0},
			response:   []byte{0x7f},
			crt:        "b603840101",
		},
		{
			name: "additional CRT malformed response",
			template: protocol.ControlReferenceTemplate{
				Tag: protocol.DigitalSignatureTemplateTag, KeyReference: protocol.AttestationKeyReference,
			},
			attributes: attributes,
			command:    []byte{0, 0x47, 0x80, 0, 5, 0xb6, 3, 0x84, 1, 0x81, 0},
			response:   []byte{0x7f},
			crt:        "b603840181",
		},
		{
			name: "additional CRT attributes mismatch",
			template: protocol.ControlReferenceTemplate{
				Tag: protocol.DigitalSignatureTemplateTag, KeyReference: protocol.AttestationKeyReference,
			},
			attributes: protocol.AlgorithmAttributes{
				Algorithm: protocol.RSA, ModulusBits: 2048, ExponentBits: 32,
			},
			command:  []byte{0, 0x47, 0x80, 0, 5, 0xb6, 3, 0x84, 1, 0x81, 0},
			response: validResponse,
			crt:      "b603840181",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := newClient(t, step{
				command: test.command, response: iso7816.Response{Status: 0x9000, Data: test.response},
			})

			public, err := c.GenerateAsymmetricKeyPairWithTemplate(t.Context(), test.template, test.attributes)

			var generated *client.KeyGenerationError
			if public != nil || !errors.As(err, &generated) || generated.Template != test.template || !errors.Is(err, protocol.ErrInvalidResponse) {
				t.Fatalf("generation = %v, %v; want acknowledged replacement of %+v", public, err, test.template)
			}

			if !strings.Contains(generated.Error(), test.crt) {
				t.Errorf("error = %q, want full CRT %s", generated.Error(), test.crt)
			}
		})
	}
}

func TestTemplateGenerationRejectionAndTransportFailureDoNotRetry(t *testing.T) {
	attributes, _, _ := controlReferenceTemplateP256Fixture(t)

	for _, test := range []struct {
		name     string
		response iso7816.Response
		err      error
	}{
		{name: "APDU rejection", response: iso7816.Response{Status: 0x6a81}},
		{name: "transport failure", err: io.ErrUnexpectedEOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := newClient(t, step{
				command:  []byte{0, 0x47, 0x80, 0, 5, 0xb6, 3, 0x84, 1, 0x81, 0},
				response: test.response, err: test.err,
			})

			public, err := c.GenerateAsymmetricKeyPairWithTemplate(t.Context(), protocol.ControlReferenceTemplate{
				Tag: protocol.DigitalSignatureTemplateTag, KeyReference: protocol.AttestationKeyReference,
			}, attributes)

			var generated *client.KeyGenerationError
			if public != nil || err == nil || errors.As(err, &generated) {
				t.Fatalf("generation = %v, %v; want unacknowledged failure", public, err)
			}

			if test.err != nil {
				if !errors.Is(err, test.err) {
					t.Errorf("error = %v, want transport cause %v", err, test.err)
				}
			} else {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6a81 {
					t.Errorf("error = %v, want APDU status 6a81", err)
				}
			}
		})
	}
}

func TestTemplateReadMalformedResponseIsNotGenerationError(t *testing.T) {
	attributes, _, _ := controlReferenceTemplateP256Fixture(t)
	c := newClient(t, step{
		command:  []byte{0, 0x47, 0x81, 0, 5, 0xb6, 3, 0x84, 1, 0x81, 0},
		response: iso7816.Response{Status: 0x9000, Data: []byte{0x7f}},
	})

	public, err := c.ReadPublicKeyWithTemplate(t.Context(), protocol.ControlReferenceTemplate{
		Tag: protocol.DigitalSignatureTemplateTag, KeyReference: protocol.AttestationKeyReference,
	}, attributes)

	var generated *client.KeyGenerationError
	if public != nil || !errors.Is(err, protocol.ErrInvalidResponse) || errors.As(err, &generated) {
		t.Fatalf("read = %v, %v; want invalid response without generation acknowledgement", public, err)
	}
}

func controlReferenceTemplateP256Fixture(t testing.TB) (protocol.AlgorithmAttributes, []byte, []byte) {
	t.Helper()

	scalar := [32]byte{31: 1}

	key, err := ecdh.P256().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatal(err)
	}

	point := key.PublicKey().Bytes()
	response := slices.Concat([]byte{0x7f, 0x49, 67, 0x86, 65}, point)
	attributes := protocol.AlgorithmAttributes{
		Algorithm: protocol.ECDSA, CurveOID: []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
	}

	return attributes, response, point
}
