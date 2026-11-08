package pcsc_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/telesma-app/bertlv"
	openpgppcsc "github.com/telesma-app/openpgp/backend/pcsc"
	"github.com/telesma-app/openpgp/card"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

// TestHardwareMSEP256 provisions ECDH-P256 DEC and ECDSA-P256 AUT on a disposable
// card, using DEC as an ECDSA key only for this MSE test. Cleanup factory-resets
// the entire OpenPGP application, erasing its keys, certificates, passwords and
// user data. It requires OPENPGP_TEST_WRITE=1, OPENPGP_TEST_RESET=1 and explicit PW1/PW3.
func TestHardwareMSEP256(t *testing.T) {
	if os.Getenv("OPENPGP_TEST_WRITE") != "1" {
		t.Skip("set OPENPGP_TEST_WRITE=1 to replace P-256 keys on a selected test card")
	}

	if os.Getenv("OPENPGP_TEST_RESET") != "1" {
		t.Skip("set OPENPGP_TEST_RESET=1 to permit factory reset of the entire OpenPGP application")
	}

	reader := os.Getenv("OPENPGP_TEST_READER")
	if reader == "" {
		t.Fatal("OPENPGP_TEST_READER must name one exact reader")
	}

	password := hardwareAESPassword(t, "OPENPGP_TEST_PW1_HEX")
	adminPassword := hardwareAESPassword(t, "OPENPGP_TEST_PW3_HEX")

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	connection, err := openpgppcsc.Open(ctx, reader)
	if err != nil {
		t.Fatal(err)
	}

	device := card.New(connection)
	cleanup := func() {
		if err := device.Close(); err != nil {
			t.Errorf("close P-256 MSE test connection: %v", err)
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

	verifyHardwareAESCredentials(t, ctx, device, password, adminPassword)

	cleanup = func() {
		if err := device.Close(); err != nil {
			t.Errorf("close P-256 MSE connection before factory reset: %v", err)
		}

		resetHardwareMSEApplication(t, reader, adminPassword)
	}

	for _, slot := range []struct {
		name       string
		object     protocol.Object
		attributes []byte
	}{
		{
			name: "DEC", object: protocol.DecryptionAlgorithmAttributesObject,
			attributes: []byte{0x12, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xff},
		},
		{
			name: "AUT", object: protocol.AuthenticationAlgorithmAttributesObject,
			attributes: []byte{0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xff},
		},
	} {
		if err := device.PutData(ctx, slot.object, slot.attributes, protocol.PW3, nil); err != nil {
			t.Fatalf("configure %s P-256 attributes: %v", slot.name, err)
		}
	}

	var decryptionKey, authenticationKey crypto.PublicKey

	if application.ExtendedCapabilities.KeyImport {
		t.Log("provisioning DEC and AUT with host-generated P-256 keys")
		decryptionKey = importHardwareMSEP256Key(t, ctx, device, protocol.ConfidentialityTemplateTag)
		authenticationKey = importHardwareMSEP256Key(t, ctx, device, protocol.AuthenticationTemplateTag)
	} else {
		t.Log("provisioning DEC and AUT with on-card P-256 generation")

		decryptionKey, err = device.GenerateAsymmetricKeyPair(ctx, protocol.ConfidentialityTemplateTag, nil)
		if err != nil {
			t.Fatalf("generate DEC P-256 key: %v", err)
		}

		authenticationKey, err = device.GenerateAsymmetricKeyPair(ctx, protocol.AuthenticationTemplateTag, nil)
		if err != nil {
			t.Fatalf("generate AUT P-256 key: %v", err)
		}
	}

	decryption, ok := decryptionKey.(*ecdh.PublicKey)
	if !ok {
		t.Fatalf("DEC public key type = %T, want ECDH", decryptionKey)
	}

	authentication, ok := authenticationKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("AUT public key type = %T, want ECDSA", authenticationKey)
	}

	authenticationECDH, err := authentication.ECDH()
	if err != nil {
		t.Fatal(err)
	}

	if decryption.Equal(authenticationECDH) {
		t.Fatal("provisioned DEC and AUT public points are identical")
	}

	// ECDH-key signing is tested here without extending PrivateKey's contract.
	decryptionECDSA, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), decryption.Bytes())
	if err != nil {
		t.Fatal(err)
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
				t.Fatalf("close short-APDU P-256 connection: %v", err)
			}

			connection, err = openpgppcsc.Open(ctx, reader)
			if err != nil {
				t.Fatal(err)
			}

			device = card.New(connection, client.WithExtendedLength())
			verifyHardwareAESCredentials(t, ctx, device, password, adminPassword)
		}

		if !t.Run(mode.name, func(t *testing.T) {
			digest := sha256.Sum256([]byte("OpenPGP MSE ECDH-P256 DEC INTERNAL AUTHENTICATE"))

			signature, err := device.InternalAuthenticateWithKey(ctx, protocol.ConfidentialityTemplateTag, digest[:], nil)
			if err != nil {
				t.Fatalf("authenticate with DEC ECDH-P256 key: %v", err)
			}

			if len(signature) != 64 {
				t.Fatalf("DEC P-256 signature length = %d, want raw r32 || s32", len(signature))
			}

			r := new(big.Int).SetBytes(signature[:32])

			s := new(big.Int).SetBytes(signature[32:])
			if !ecdsa.Verify(decryptionECDSA, digest[:], r, s) {
				t.Fatal("DEC P-256 signature does not match the DEC public point")
			}

			binding, err := device.PrivateKey(ctx, protocol.AuthenticationTemplateTag)
			if err != nil {
				t.Fatalf("bind default AUT ECDSA-P256 key: %v", err)
			}

			if !authentication.Equal(binding.Public()) {
				t.Fatal("bound AUT key differs from the provisioned public key")
			}

			authenticationDigest := sha256.Sum256([]byte("OpenPGP default AUT after ECDH-P256 DEC signing"))

			signature, err = binding.Signer(ctx, nil).Sign(nil, authenticationDigest[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("sign with default AUT after DEC signing: %v", err)
			}

			if !ecdsa.VerifyASN1(authentication, authenticationDigest[:], signature) {
				t.Fatal("restored AUT signature does not match the AUT public key")
			}

			peer, err := ecdh.P256().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			input := bertlv.Append(nil, 0xa6, bertlv.Append(nil, 0x7f49,
				bertlv.Append(nil, 0x86, peer.PublicKey().Bytes())))

			wantAuthentication, err := peer.ECDH(authenticationECDH)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(wantAuthentication)

			gotAuthentication, err := device.DecipherWithKey(ctx, protocol.AuthenticationTemplateTag, input, nil)
			defer clear(gotAuthentication)

			if err != nil {
				t.Fatalf("ECDH with AUT ECDSA-P256 key: %v", err)
			}

			if !bytes.Equal(gotAuthentication, wantAuthentication) {
				t.Fatal("AUT ECDH shared secret differs from the host result")
			}

			wantDecryption, err := peer.ECDH(decryption)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(wantDecryption)

			gotDecryption, err := device.Decipher(ctx, input, nil)
			defer clear(gotDecryption)

			if err != nil {
				t.Fatalf("default DEC ECDH after AUT ECDH: %v", err)
			}

			if !bytes.Equal(gotDecryption, wantDecryption) {
				t.Error("restored DEC ECDH shared secret differs from the host result")
			}
		}) {
			return
		}
	}
}

func importHardwareMSEP256Key(t testing.TB, ctx context.Context, device *card.Device, reference protocol.ControlReferenceTemplateTag) crypto.PublicKey {
	t.Helper()

	attributes := protocol.AlgorithmAttributes{
		CurveOID: []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}, ImportFormat: 0xff,
	}

	var (
		private crypto.PrivateKey
		public  []byte
	)

	switch reference {
	case protocol.ConfidentialityTemplateTag:
		key, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		attributes.Algorithm = protocol.ECDH
		private = key
		public = key.PublicKey().Bytes()
	case protocol.AuthenticationTemplateTag:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		attributes.Algorithm = protocol.ECDSA
		private = key

		public, err = key.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
	default:
		panic("P-256 MSE fixture requires a DEC or AUT key")
	}

	if err := device.ImportKeyWithTemplate(ctx, protocol.ControlReferenceTemplate{Tag: reference}, attributes, private, nil); err != nil {
		t.Fatalf("import P-256 key %02x: %v", byte(reference), err)
	}

	imported, err := device.ReadPublicKey(ctx, reference)
	if err != nil {
		t.Fatalf("read imported P-256 key %02x: %v", byte(reference), err)
	}

	var importedPoint []byte

	switch imported := imported.(type) {
	case *ecdh.PublicKey:
		importedPoint = imported.Bytes()
	case *ecdsa.PublicKey:
		importedPoint, err = imported.Bytes()
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("imported P-256 key type = %T, want ECDH or ECDSA", imported)
	}

	if !bytes.Equal(importedPoint, public) {
		t.Fatalf("imported P-256 key %02x differs from the host public point", byte(reference))
	}

	return imported
}
