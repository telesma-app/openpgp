package client_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"errors"
	"io"
	"slices"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestGenerationAcknowledgedWithMalformedPublicKey(t *testing.T) {
	c := newClient(t,
		step{command: []byte{0, 0xca, 0, 0x6e, 0}, response: iso7816.Response{Status: 0x9000, Data: signatureApplication}},
		step{command: []byte{0, 0x47, 0x80, 0, 2, 0xb6, 0, 0}, response: iso7816.Response{Status: 0x9000, Data: []byte{0x7f}}},
	)
	_, err := c.GenerateAsymmetricKeyPair(t.Context(), protocol.DigitalSignatureTemplateTag)

	var generated *client.KeyGenerationError
	if !errors.As(err, &generated) || generated.Template != (protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag}) || !errors.Is(err, protocol.ErrInvalidResponse) {
		t.Fatalf("generation error = %v", err)
	}
}

func TestGenerationRejectsUnsupportedCardAlgorithmBeforeReplacement(t *testing.T) {
	// An unknown algorithm ID is valid metadata but cannot be parsed into a Go
	// public key. No GENERATE command should be sent after discovering it.
	application := []byte{
		0x6e, 0x17, 0x4f, 0x10, 0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 0, 0, 0, 0, 1, 0, 0,
		0x73, 3, 0xc1, 1, 99,
	}
	c := newClient(t, step{command: []byte{0, 0xca, 0, 0x6e, 0}, response: iso7816.Response{Status: 0x9000, Data: application}})

	_, err := c.GenerateAsymmetricKeyPair(t.Context(), protocol.DigitalSignatureTemplateTag)
	if !errors.Is(err, protocol.ErrUnsupportedAlgorithm) {
		t.Fatalf("generation error = %v", err)
	}
}

func TestGenerationTransportFailureHasUnknownEffect(t *testing.T) {
	c := newClient(t,
		step{command: []byte{0, 0xca, 0, 0x6e, 0}, response: iso7816.Response{Status: 0x9000, Data: signatureApplication}},
		step{command: []byte{0, 0x47, 0x80, 0, 2, 0xb6, 0, 0}, err: io.ErrUnexpectedEOF},
	)
	_, err := c.GenerateAsymmetricKeyPair(t.Context(), protocol.DigitalSignatureTemplateTag)

	var generated *client.KeyGenerationError
	if !errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &generated) {
		t.Fatalf("generation error = %v", err)
	}
}

func TestReadExistingPublicKey(t *testing.T) {
	scalar := [32]byte{31: 1}

	key, err := ecdh.P256().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatal(err)
	}

	point := key.PublicKey().Bytes()
	response := slices.Concat([]byte{0x7f, 0x49, 67, 0x86, 65}, point)
	c := newClient(t,
		step{command: []byte{0, 0xca, 0, 0x6e, 0}, response: iso7816.Response{Status: 0x9000, Data: signatureApplication}},
		step{command: []byte{0, 0x47, 0x81, 0, 2, 0xb6, 0, 0}, response: iso7816.Response{Status: 0x9000, Data: response}},
	)

	public, err := c.ReadPublicKey(t.Context(), protocol.DigitalSignatureTemplateTag)
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
}
