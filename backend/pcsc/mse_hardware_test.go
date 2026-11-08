package pcsc_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
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

// TestHardwareMSE replaces DEC/AUT with distinct RSA-2048 keys on a disposable
// card. Cleanup factory-resets the entire OpenPGP application, erasing its keys,
// certificates, passwords and user data. It requires OPENPGP_TEST_WRITE=1,
// OPENPGP_TEST_RESET=1 and explicit encoded PW1/PW3.
func TestHardwareMSE(t *testing.T) {
	if os.Getenv("OPENPGP_TEST_WRITE") != "1" {
		t.Skip("set OPENPGP_TEST_WRITE=1 to replace keys on a selected test card")
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

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	connection, err := openpgppcsc.Open(ctx, reader)
	if err != nil {
		t.Fatal(err)
	}

	device := card.New(connection)
	cleanup := func() {
		if err := device.Close(); err != nil {
			t.Errorf("close MSE test connection: %v", err)
		}
	}

	t.Cleanup(func() { cleanup() })

	application, err := device.GetApplicationRelatedData(ctx)
	if err != nil {
		t.Fatalf("read application capabilities: %v", err)
	}

	if application.ExtendedCapabilities == nil || !application.ExtendedCapabilities.ManageSecurityEnvironment {
		t.Skip("card does not announce MANAGE SECURITY ENVIRONMENT support")
	}

	verifyHardwareCredentials(t, ctx, device, password, adminPassword)

	cleanup = func() {
		if err := device.Close(); err != nil {
			t.Errorf("close MSE test connection before factory reset: %v", err)
		}

		resetHardwareApplication(t, reader, adminPassword)
	}

	for _, slot := range []struct {
		name       string
		object     protocol.Object
		attributes protocol.AlgorithmAttributes
	}{
		{name: "DEC", object: protocol.DecryptionAlgorithmAttributesObject, attributes: application.DecryptionAlgorithmAttributes},
		{name: "AUT", object: protocol.AuthenticationAlgorithmAttributesObject, attributes: application.AuthenticationAlgorithmAttributes},
	} {
		if slot.attributes.Algorithm != protocol.RSA || slot.attributes.ModulusBits != 2048 ||
			(application.ExtendedCapabilities.KeyImport && (slot.attributes.ExponentBits != 32 || slot.attributes.ImportFormat != 0)) {
			// RSA, 2048-bit modulus, 32-bit exponent, standard import format.
			if err := device.PutData(ctx, slot.object, []byte{0x01, 0x08, 0x00, 0x00, 0x20, 0x00}, protocol.PW3, nil); err != nil {
				t.Fatalf("configure %s RSA-2048 attributes: %v", slot.name, err)
			}
		}
	}

	var decryption, authentication *rsa.PublicKey

	if application.ExtendedCapabilities.KeyImport {
		t.Log("provisioning DEC and AUT with host-generated RSA-2048 keys")
		decryption = importHardwareRSAKey(t, ctx, device, protocol.ConfidentialityTemplateTag)
		authentication = importHardwareRSAKey(t, ctx, device, protocol.AuthenticationTemplateTag)
	} else {
		t.Log("provisioning DEC and AUT with on-card RSA-2048 generation")
		decryption = generateHardwareRSAKey(t, ctx, device, protocol.ConfidentialityTemplateTag)
		authentication = generateHardwareRSAKey(t, ctx, device, protocol.AuthenticationTemplateTag)
	}

	if decryption.Equal(authentication) {
		t.Fatal("provisioned DEC and AUT public keys are identical")
	}

	for _, mode := range []struct {
		name     string
		extended bool
	}{
		{name: "short"},
		{name: "extended", extended: true},
	} {
		if mode.extended {
			if err := device.Close(); err != nil {
				t.Fatalf("close short-APDU connection: %v", err)
			}

			connection, err = openpgppcsc.Open(ctx, reader)
			if err != nil {
				t.Fatal(err)
			}

			device = card.New(connection, client.WithExtendedLength())
			verifyHardwareCredentials(t, ctx, device, password, adminPassword)
		}

		if !t.Run(mode.name, func(t *testing.T) {
			decryptionKey, err := device.PrivateKey(ctx, protocol.ConfidentialityTemplateTag)
			if err != nil {
				t.Fatalf("bind DEC signing key: %v", err)
			}

			authenticationKey, err := device.PrivateKey(ctx, protocol.AuthenticationTemplateTag)
			if err != nil {
				t.Fatalf("bind AUT signing key: %v", err)
			}

			if !decryption.Equal(decryptionKey.Public()) || !authentication.Equal(authenticationKey.Public()) {
				t.Fatal("bound public keys differ from the provisioned DEC and AUT keys")
			}

			decryptionDigest := sha256.Sum256([]byte("OpenPGP MSE DEC INTERNAL AUTHENTICATE"))

			signature, err := decryptionKey.Signer(ctx, nil).Sign(nil, decryptionDigest[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("sign with DEC key: %v", err)
			}

			if err := rsa.VerifyPKCS1v15(decryption, crypto.SHA256, decryptionDigest[:], signature); err != nil {
				t.Fatalf("verify DEC signature: %v", err)
			}

			authenticationDigest := sha256.Sum256([]byte("OpenPGP default AUT after MSE DEC signing"))

			signature, err = authenticationKey.Signer(ctx, nil).Sign(nil, authenticationDigest[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("sign with default AUT key after DEC signing: %v", err)
			}

			if err := rsa.VerifyPKCS1v15(authentication, crypto.SHA256, authenticationDigest[:], signature); err != nil {
				t.Fatalf("verify restored AUT signature: %v", err)
			}

			authenticationPlaintext := []byte("OpenPGP MSE AUT PSO DECIPHER")

			//nolint:staticcheck // OpenPGP Card PSO:DECIPHER uses RSA PKCS#1 v1.5 padding.
			ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, authentication, authenticationPlaintext)
			if err != nil {
				t.Fatal(err)
			}

			plain, err := device.DecipherWithKey(ctx, protocol.AuthenticationTemplateTag, append([]byte{0x00}, ciphertext...), nil)
			if err != nil {
				t.Fatalf("decipher with AUT key: %v", err)
			}

			if !bytes.Equal(plain, authenticationPlaintext) {
				t.Fatalf("AUT plaintext = %x, want %x", plain, authenticationPlaintext)
			}

			decryptionPlaintext := []byte("OpenPGP default DEC after MSE AUT decryption")

			//nolint:staticcheck // OpenPGP Card PSO:DECIPHER uses RSA PKCS#1 v1.5 padding.
			ciphertext, err = rsa.EncryptPKCS1v15(rand.Reader, decryption, decryptionPlaintext)
			if err != nil {
				t.Fatal(err)
			}

			plain, err = device.Decipher(ctx, append([]byte{0x00}, ciphertext...), nil)
			if err != nil {
				t.Fatalf("decipher with default DEC key after AUT decryption: %v", err)
			}

			if !bytes.Equal(plain, decryptionPlaintext) {
				t.Errorf("restored DEC plaintext = %x, want %x", plain, decryptionPlaintext)
			}
		}) {
			return
		}
	}
}

func importHardwareRSAKey(t testing.TB, ctx context.Context, device *card.Device, reference protocol.ControlReferenceTemplateTag) *rsa.PublicKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	if err := device.ImportKeyWithTemplate(ctx, protocol.ControlReferenceTemplate{Tag: reference}, protocol.AlgorithmAttributes{
		Algorithm: protocol.RSA, ModulusBits: 2048, ExponentBits: 32, ImportFormat: 0,
	}, key, nil); err != nil {
		var apdu *baseiso7816.APDUError
		if errors.As(err, &apdu) && apdu.StatusWord() == 0x6a81 {
			t.Skip("card supports MSE but rejects RSA-2048 key import (SW=6a81)")
		}

		t.Fatalf("import key %02x: %v", byte(reference), err)
	}

	imported, err := device.ReadPublicKey(ctx, reference)
	if err != nil {
		t.Fatalf("read imported key %02x: %v", byte(reference), err)
	}

	publicKey, ok := imported.(*rsa.PublicKey)
	if !ok || !key.PublicKey.Equal(publicKey) {
		t.Fatalf("imported key %02x does not match the host-generated public key", byte(reference))
	}

	return publicKey
}

func generateHardwareRSAKey(t testing.TB, ctx context.Context, device *card.Device, reference protocol.ControlReferenceTemplateTag) *rsa.PublicKey {
	t.Helper()

	generated, err := device.GenerateAsymmetricKeyPair(ctx, reference, nil)
	if err != nil {
		var apdu *baseiso7816.APDUError
		if errors.As(err, &apdu) && apdu.StatusWord() == 0x6a81 {
			t.Skip("card supports MSE but rejects RSA-2048 key generation (SW=6a81)")
		}

		t.Fatalf("generate key %02x: %v", byte(reference), err)
	}

	publicKey, ok := generated.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("generated key %02x type = %T, want RSA", byte(reference), generated)
	}

	if publicKey.N.BitLen() != 2048 {
		t.Fatalf("generated key %02x modulus = %d bits, want 2048", byte(reference), publicKey.N.BitLen())
	}

	return publicKey
}
