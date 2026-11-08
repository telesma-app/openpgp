package pcsc_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/telesma-app/bertlv"
	baseiso7816 "github.com/telesma-app/iso7816"
	openpgppcsc "github.com/telesma-app/openpgp/backend/pcsc"
	"github.com/telesma-app/openpgp/card"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

// TestHardwareImportKey imports only ordinary DEC and AUT keys on one exact
// reader. Both slots and their metadata must initially be empty. The selected
// card's attribute setter must have reviewed selected-slot deletion semantics.
// Cleanup changes only C2/C3 to delete test keys, then restores their original
// values. It never factory-resets the application or writes attestation objects.
func TestHardwareImportKey(t *testing.T) {
	if os.Getenv("OPENPGP_TEST_WRITE") != "1" {
		t.Skip("set OPENPGP_TEST_WRITE=1 to import ordinary DEC/AUT keys on a selected test card")
	}

	reader := os.Getenv("OPENPGP_TEST_READER")
	if reader == "" {
		t.Fatal("OPENPGP_TEST_READER must name one exact reader")
	}

	password := hardwarePassword(t, "OPENPGP_TEST_PW1_HEX")
	adminPassword := hardwarePassword(t, "OPENPGP_TEST_PW3_HEX")

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()

	connection, err := openpgppcsc.Open(ctx, reader)
	if err != nil {
		t.Fatal(err)
	}

	device := card.New(connection)
	cleanup := func() {
		if err := device.Close(); err != nil {
			t.Errorf("close import test connection: %v", err)
		}
	}

	t.Cleanup(func() { cleanup() })

	application, err := device.GetApplicationRelatedData(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if application.ExtendedCapabilities == nil || !application.ExtendedCapabilities.KeyImport || !application.ExtendedCapabilities.AlgorithmAttributesChangeable {
		t.Skip("card must announce key import and changeable algorithm attributes")
	}

	if len(application.DecryptionAlgorithmAttributes.Raw) == 0 || len(application.AuthenticationAlgorithmAttributes.Raw) == 0 {
		t.Fatal("current DEC/AUT attributes are required for restoration")
	}

	empty, err := hardwareImportTargetsEmpty(ctx, device, application)
	if err != nil {
		t.Fatalf("inspect original DEC/AUT state: %v", err)
	}

	if !empty {
		t.Skip("ordinary DEC/AUT keys, fingerprints, creation times and certificates must be empty")
	}

	originalDEC := bytes.Clone(application.DecryptionAlgorithmAttributes.Raw)
	originalAUT := bytes.Clone(application.AuthenticationAlgorithmAttributes.Raw)

	verifyHardwareCredentials(t, ctx, device, password, adminPassword)

	cleanup = func() {
		if err := device.Close(); err != nil {
			t.Errorf("close import connection before restoring DEC/AUT: %v", err)
		}

		cleanupHardwareImportedKeys(t, reader, adminPassword, originalDEC, originalAUT)
	}

	rsaFormat, exponentBits := protocol.ImportFormatStandard, uint16(32)
	if application.AuthenticationAlgorithmAttributes.Algorithm == protocol.RSA {
		rsaFormat = application.AuthenticationAlgorithmAttributes.ImportFormat
		exponentBits = application.AuthenticationAlgorithmAttributes.ExponentBits
	}

	profiles := []struct {
		name        string
		reference   protocol.ControlReferenceTemplateTag
		attributes  []byte
		useTemplate bool
		newKey      func() (crypto.PrivateKey, error)
	}{
		{
			name: "AUT_RSA2048", reference: protocol.AuthenticationTemplateTag,
			attributes: []byte{1, 8, 0, byte(exponentBits >> 8), byte(exponentBits), byte(rsaFormat)},
			newKey:     func() (crypto.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) },
		},
		{
			name: "AUT_P256", reference: protocol.AuthenticationTemplateTag, useTemplate: true,
			attributes: []byte{0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7, 0xff},
			newKey:     func() (crypto.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) },
		},
		{
			name: "AUT_P384", reference: protocol.AuthenticationTemplateTag,
			attributes: []byte{0x13, 0x2b, 0x81, 4, 0, 0x22, 0xff},
			newKey:     func() (crypto.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) },
		},
		{
			name: "AUT_P521", reference: protocol.AuthenticationTemplateTag, useTemplate: true,
			attributes: []byte{0x13, 0x2b, 0x81, 4, 0, 0x23, 0xff},
			newKey:     func() (crypto.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P521(), rand.Reader) },
		},
		{
			name: "AUT_Ed25519", reference: protocol.AuthenticationTemplateTag,
			attributes: []byte{0x16, 0x2b, 6, 1, 4, 1, 0xda, 0x47, 0x0f, 1, 0xff},
			newKey: func() (crypto.PrivateKey, error) {
				_, key, err := ed25519.GenerateKey(rand.Reader)
				return key, err
			},
		},
		{
			name: "DEC_P256", reference: protocol.ConfidentialityTemplateTag, useTemplate: true,
			attributes: []byte{0x12, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7, 0xff},
			newKey:     func() (crypto.PrivateKey, error) { return ecdh.P256().GenerateKey(rand.Reader) },
		},
		{
			name: "DEC_P384", reference: protocol.ConfidentialityTemplateTag,
			attributes: []byte{0x12, 0x2b, 0x81, 4, 0, 0x22, 0xff},
			newKey:     func() (crypto.PrivateKey, error) { return ecdh.P384().GenerateKey(rand.Reader) },
		},
		{
			name: "DEC_P521", reference: protocol.ConfidentialityTemplateTag, useTemplate: true,
			attributes: []byte{0x12, 0x2b, 0x81, 4, 0, 0x23, 0xff},
			newKey:     func() (crypto.PrivateKey, error) { return ecdh.P521().GenerateKey(rand.Reader) },
		},
		{
			name: "DEC_X25519", reference: protocol.ConfidentialityTemplateTag,
			attributes: []byte{0x12, 0x2b, 6, 1, 4, 1, 0x97, 0x55, 1, 5, 1, 0xff},
			newKey:     func() (crypto.PrivateKey, error) { return ecdh.X25519().GenerateKey(rand.Reader) },
		},
	}
	for _, mode := range []struct {
		name     string
		extended bool
	}{
		{name: "short"},
		{name: "extended", extended: true},
	} {
		if !t.Run(mode.name, func(t *testing.T) {
			if mode.extended {
				if err := device.Close(); err != nil {
					t.Fatal(err)
				}

				connection, err = openpgppcsc.Open(ctx, reader)
				if err != nil {
					t.Fatal(err)
				}

				device = card.New(connection, client.WithExtendedLength())
				verifyHardwareCredentials(t, ctx, device, password, adminPassword)
			}

			for _, profile := range profiles {
				if !t.Run(profile.name, func(t *testing.T) {
					object := protocol.AuthenticationAlgorithmAttributesObject
					if profile.reference == protocol.ConfidentialityTemplateTag {
						object = protocol.DecryptionAlgorithmAttributesObject
					}

					if err := device.PutData(ctx, object, profile.attributes, protocol.PW3, nil); err != nil {
						var apdu *baseiso7816.APDUError
						if errors.As(err, &apdu) && (apdu.StatusWord() == 0x6a81 || apdu.StatusWord() == 0x6a80 || apdu.StatusWord() == 0x6b00) {
							t.Skipf("card rejects requested algorithm attributes (SW=%s)", apdu.StatusWord())
						}

						t.Fatalf("set current attributes: %v", err)
					}

					current, err := device.GetApplicationRelatedData(ctx)
					if err != nil {
						t.Fatal(err)
					}

					attributes := current.AuthenticationAlgorithmAttributes
					if profile.reference == protocol.ConfidentialityTemplateTag {
						attributes = current.DecryptionAlgorithmAttributes
					}

					if !bytes.Equal(attributes.Raw, profile.attributes) {
						t.Skipf("card reports different current attributes: got %x, requested %x", attributes.Raw, profile.attributes)
					}

					key, err := profile.newKey()
					if err != nil {
						t.Fatal(err)
					}

					if key, ok := key.(ed25519.PrivateKey); ok {
						defer clear(key)
					}

					if profile.useTemplate {
						number := protocol.AuthenticationKeyReference
						if profile.reference == protocol.ConfidentialityTemplateTag {
							number = protocol.DecryptionKeyReference
						}

						err = device.ImportKeyWithTemplate(ctx, protocol.ControlReferenceTemplate{Tag: profile.reference, KeyReference: number}, attributes, key, nil)
					} else {
						err = device.ImportKey(ctx, profile.reference, key, nil)
					}

					if err != nil {
						skipUnsupportedHardwareImport(t, err)
						t.Fatalf("import with confirmed current attributes: %v", err)
					}

					verifyHardwareImportedKey(t, ctx, device, profile.reference, key, password)
				}) {
					return
				}
			}
		}) {
			return
		}
	}
}

func hardwareImportTargetsEmpty(ctx context.Context, device *card.Device, application protocol.ApplicationRelatedData) (bool, error) {
	data, err := device.GetData(ctx, protocol.KeyInformationObject)
	if err != nil {
		return false, fmt.Errorf("read key information: %w", err)
	}

	keys, err := protocol.ParseKeyInformation(data)
	if err != nil {
		return false, err
	}

	if len(application.Fingerprints) < 3 || len(application.KeyGenerationTimes) < 3 {
		return false, errors.New("DEC/AUT fingerprint and creation-time metadata must be available")
	}

	for _, index := range []int{1, 2} {
		if byte(keys[index].Reference) != byte(index+1) {
			return false, fmt.Errorf("cannot identify ordinary key reference %d", index+1)
		}

		if keys[index].Status != 0 || application.Fingerprints[index] != ([20]byte{}) || application.KeyGenerationTimes[index] != 0 {
			return false, nil
		}
	}

	certificates, err := device.GetCardholderCertificates(ctx)
	if err != nil {
		return false, err
	}

	return len(certificates.Authentication) == 0 && len(certificates.Decryption) == 0, nil
}

func skipUnsupportedHardwareImport(t testing.TB, err error) {
	t.Helper()

	var apdu *baseiso7816.APDUError
	if errors.As(err, &apdu) && apdu.StatusWord() == 0x6a81 {
		t.Skip("card backend does not support this profile operation (SW=6a81)")
	}
}

func verifyHardwareImportedKey(t *testing.T, ctx context.Context, device *card.Device, reference protocol.ControlReferenceTemplateTag, key crypto.PrivateKey, password []byte) {
	t.Helper()

	public, err := device.ReadPublicKey(ctx, reference)
	if err != nil {
		skipUnsupportedHardwareImport(t, err)
		t.Fatalf("read imported public key: %v", err)
	}

	if reference == protocol.ConfidentialityTemplateTag {
		private := key.(*ecdh.PrivateKey)
		if !private.PublicKey().Equal(public) {
			t.Fatal("imported DEC public key differs from the host key")
		}

		peer, err := private.Curve().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		input := bertlv.Append(nil, 0xa6, bertlv.Append(nil, 0x7f49,
			bertlv.Append(nil, 0x86, peer.PublicKey().Bytes())))

		want, err := private.ECDH(peer.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		defer clear(want)

		got, err := device.Decipher(ctx, input, nil)
		defer clear(got)

		if err != nil {
			skipUnsupportedHardwareImport(t, err)
			t.Fatalf("use imported DEC private key: %v", err)
		}

		if !bytes.Equal(got, want) {
			t.Fatal("imported DEC ECDH shared secret differs from the host result")
		}

		return
	}

	message := []byte("OpenPGP imported ordinary AUT private-key possession")
	input := message
	hash := crypto.Hash(0)

	var matches bool

	switch private := key.(type) {
	case *rsa.PrivateKey:
		matches = private.PublicKey.Equal(public)
		digest := sha256.Sum256(message)
		input, hash = digest[:], crypto.SHA256
	case *ecdsa.PrivateKey:
		matches = private.PublicKey.Equal(public)
		switch private.Params().BitSize {
		case 384:
			digest := sha512.Sum384(message)
			input, hash = digest[:], crypto.SHA384
		case 521:
			digest := sha512.Sum512(message)
			input, hash = digest[:], crypto.SHA512
		default:
			digest := sha256.Sum256(message)
			input, hash = digest[:], crypto.SHA256
		}
	case ed25519.PrivateKey:
		matches = private.Public().(ed25519.PublicKey).Equal(public)
	default:
		panic("unexpected AUT import fixture type")
	}

	if !matches {
		t.Fatal("imported AUT public key differs from the host key")
	}

	binding, err := device.PrivateKey(ctx, reference)
	if err != nil {
		t.Fatalf("bind imported AUT key: %v", err)
	}

	authentication := card.AuthenticationSource(func(context.Context) ([]byte, error) {
		return bytes.Clone(password), nil
	})

	signature, err := binding.Signer(ctx, authentication).Sign(nil, input, hash)
	if err != nil {
		skipUnsupportedHardwareImport(t, err)
		t.Fatalf("sign with imported AUT key: %v", err)
	}

	switch public := public.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(public, hash, input, signature); err != nil {
			t.Fatalf("verify imported AUT RSA signature: %v", err)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(public, input, signature) {
			t.Fatal("imported AUT ECDSA signature does not match the host key")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(public, input, signature) {
			t.Fatal("imported AUT Ed25519 signature does not match the host key")
		}
	}
}

func cleanupHardwareImportedKeys(t *testing.T, reader string, password, originalDEC, originalAUT []byte) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	connection, err := openpgppcsc.Open(ctx, reader)
	if err != nil {
		t.Errorf("reopen selected reader for targeted import cleanup: %v", err)
		return
	}

	device := card.New(connection)
	defer func() {
		if err := device.Close(); err != nil {
			t.Errorf("close targeted cleanup connection: %v", err)
		}
	}()

	if err := device.Verify(ctx, protocol.PW3, password); err != nil {
		t.Errorf("verify configured PW3 for targeted cleanup: %v", err)
		return
	}

	for _, slot := range []struct {
		name      string
		reference protocol.ControlReferenceTemplateTag
		object    protocol.Object
		original  []byte
	}{
		{name: "DEC", reference: protocol.ConfidentialityTemplateTag, object: protocol.DecryptionAlgorithmAttributesObject, original: originalDEC},
		{name: "AUT", reference: protocol.AuthenticationTemplateTag, object: protocol.AuthenticationAlgorithmAttributesObject, original: originalAUT},
	} {
		current, err := device.GetApplicationRelatedData(ctx)
		if err != nil {
			t.Errorf("read %s algorithm before cleanup: %v", slot.name, err)
		} else {
			attributes := current.AuthenticationAlgorithmAttributes
			if slot.reference == protocol.ConfidentialityTemplateTag {
				attributes = current.DecryptionAlgorithmAttributes
			}

			alternate := []byte{1, 8, 0, 0, 32, 0}

			if attributes.Algorithm == protocol.RSA {
				algorithm := byte(protocol.ECDSA)
				if slot.reference == protocol.ConfidentialityTemplateTag {
					algorithm = byte(protocol.ECDH)
				}

				alternate = []byte{algorithm, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7, 0xff}
			}

			if err := device.PutData(ctx, slot.object, alternate, protocol.PW3, nil); err != nil {
				t.Errorf("delete %s test key by changing its algorithm: %v", slot.name, err)
			}
		}

		if err := device.PutData(ctx, slot.object, slot.original, protocol.PW3, nil); err != nil {
			t.Errorf("restore original %s algorithm attributes: %v", slot.name, err)
		}
	}

	current, err := device.GetApplicationRelatedData(ctx)
	if err != nil {
		t.Errorf("read restored DEC/AUT attributes: %v", err)
		return
	}

	if !bytes.Equal(current.DecryptionAlgorithmAttributes.Raw, originalDEC) || !bytes.Equal(current.AuthenticationAlgorithmAttributes.Raw, originalAUT) {
		t.Error("DEC/AUT algorithm attributes were not restored exactly")
	}

	empty, err := hardwareImportTargetsEmpty(ctx, device, current)
	if err != nil {
		t.Errorf("check DEC/AUT state after targeted cleanup: %v", err)
	} else if !empty {
		t.Error("DEC/AUT keys or metadata remain after targeted cleanup")
	}

	for _, reference := range []protocol.ControlReferenceTemplateTag{protocol.ConfidentialityTemplateTag, protocol.AuthenticationTemplateTag} {
		public, err := device.ReadPublicKey(ctx, reference)

		var apdu *baseiso7816.APDUError
		if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6a88 || public != nil {
			t.Errorf("key %02x after targeted cleanup = %T, %v; want absent (6a88)", byte(reference), public, err)
		}
	}
}
