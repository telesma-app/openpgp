package pcsc_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"

	baseiso7816 "github.com/telesma-app/iso7816"
	openpgppcsc "github.com/telesma-app/openpgp/backend/pcsc"
	"github.com/telesma-app/openpgp/card"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

// TestHardwareControlReferenceTemplateGenerate replaces only standard SIG key 1
// using an extended CRT, then reads and signs with short and extended APDUs.
// Cleanup factory-resets the entire OpenPGP application, erasing its keys,
// certificates, passwords and user data. It requires OPENPGP_TEST_WRITE=1,
// OPENPGP_TEST_RESET=1, explicit PW1/PW3 and an exact reader name.
func TestHardwareControlReferenceTemplateGenerate(t *testing.T) {
	if os.Getenv("OPENPGP_TEST_WRITE") != "1" {
		t.Skip("set OPENPGP_TEST_WRITE=1 to replace the standard SIG key on a test card")
	}

	if os.Getenv("OPENPGP_TEST_RESET") != "1" {
		t.Skip("set OPENPGP_TEST_RESET=1 to permit factory reset of the entire OpenPGP application")
	}

	reader := os.Getenv("OPENPGP_TEST_READER")
	if reader == "" {
		t.Fatal("OPENPGP_TEST_READER must name one exact reader")
	}

	password := hardwarePassword(t, "OPENPGP_TEST_PW1_HEX")
	adminPassword := hardwarePassword(t, "OPENPGP_TEST_PW3_HEX")

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()

	connection, err := openpgppcsc.Open(ctx, reader)
	if err != nil {
		t.Fatal(err)
	}

	device := card.New(connection)
	cleanup := func() {
		if err := device.Close(); err != nil {
			t.Errorf("close key-template test connection: %v", err)
		}
	}

	t.Cleanup(func() { cleanup() })

	verifyHardwareCredentials(t, ctx, device, password, adminPassword)

	cleanup = func() {
		if err := device.Close(); err != nil {
			t.Errorf("close key-template connection before factory reset: %v", err)
		}

		resetHardwareApplication(t, reader, adminPassword)
	}

	encodedAttributes := []byte{0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xff}

	attributes, err := protocol.ParseAlgorithmAttributes(encodedAttributes)
	if err != nil {
		t.Fatal(err)
	}

	if err := device.PutData(ctx, protocol.SignatureAlgorithmAttributesObject, encodedAttributes, protocol.PW3, nil); err != nil {
		t.Fatalf("configure standard SIG ECDSA-P256 attributes: %v", err)
	}

	template := protocol.ControlReferenceTemplate{
		Tag: protocol.DigitalSignatureTemplateTag, KeyReference: protocol.SignatureKeyReference,
	}

	generated, err := device.GenerateAsymmetricKeyPairWithTemplate(ctx, template, attributes, nil)
	if err != nil {
		var apdu *baseiso7816.APDUError
		if errors.As(err, &apdu) && apdu.StatusWord() == 0x6a81 {
			t.Skip("card rejects on-card ECDSA-P256 generation (SW=6a81)")
		}

		t.Fatalf("generate standard SIG with extended CRT: %v", err)
	}

	publicKey, ok := generated.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("generated public key type = %T, want ECDSA", generated)
	}

	t.Log("generated standard SIG once using explicit key number 1")

	for _, mode := range []struct {
		name     string
		extended bool
	}{
		{name: "short"},
		{name: "extended", extended: true},
	} {
		if mode.extended {
			if err := device.Close(); err != nil {
				t.Fatalf("close short-APDU key-template connection: %v", err)
			}

			connection, err = openpgppcsc.Open(ctx, reader)
			if err != nil {
				t.Fatal(err)
			}

			device = card.New(connection, client.WithExtendedLength())
		}

		if !t.Run(mode.name, func(t *testing.T) {
			for _, selection := range []struct {
				name string
				read func() (crypto.PublicKey, error)
			}{
				{
					name: "short SIG CRT",
					read: func() (crypto.PublicKey, error) {
						return device.ReadPublicKeyWithTemplate(ctx, protocol.ControlReferenceTemplate{
							Tag: protocol.DigitalSignatureTemplateTag,
						}, attributes)
					},
				},
				{
					name: "extended SIG CRT",
					read: func() (crypto.PublicKey, error) {
						return device.ReadPublicKeyWithTemplate(ctx, template, attributes)
					},
				},
				{
					name: "standard SIG convenience",
					read: func() (crypto.PublicKey, error) {
						return device.ReadPublicKey(ctx, protocol.DigitalSignatureTemplateTag)
					},
				},
			} {
				read, err := selection.read()
				if err != nil {
					t.Fatalf("read %s: %v", selection.name, err)
				}

				if !publicKey.Equal(read) {
					t.Fatalf("%s does not select the generated standard SIG key", selection.name)
				}
			}

			binding, err := device.PrivateKey(ctx, protocol.DigitalSignatureTemplateTag)
			if err != nil {
				t.Fatalf("bind standard SIG private key: %v", err)
			}

			if !publicKey.Equal(binding.Public()) {
				t.Fatal("standard SIG binding differs from the generated key")
			}

			if err := device.Verify(ctx, protocol.PW1Sign, password); err != nil {
				t.Fatalf("verify configured PW1 for standard SIG: %v", err)
			}

			digest := sha256.Sum256([]byte("OpenPGP extended CRT standard SIG private-key possession"))

			signature, err := binding.Signer(ctx, nil).Sign(nil, digest[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("sign with standard SIG after extended CRT generation: %v", err)
			}

			if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
				t.Error("standard SIG signature does not match the generated public key")
			}
		}) {
			return
		}
	}
}
