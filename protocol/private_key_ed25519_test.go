package protocol

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"slices"
	"testing"
)

func TestEncodeEd25519KeyImportRFC8032(t *testing.T) {
	// RFC 8032, Sec. 7.1, TEST 1. The private material is the seed, not the
	// 64-byte Go private key or the expanded and clamped signing scalar.
	const (
		seedHex   = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
		publicHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	)

	seed := curve25519ImportHex(t, seedHex)
	defer clear(seed)

	public := curve25519ImportHex(t, publicHex)

	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)

	original := slices.Clone(key)
	defer clear(original)

	if !bytes.Equal(key.Public().(ed25519.PublicKey), public) {
		t.Fatal("RFC 8032 fixture does not match the expected public key")
	}

	for _, oid := range []struct {
		name  string
		value []byte
	}{
		{name: "legacy", value: []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01}},
		{name: "RFC 8410", value: []byte{0x2b, 0x65, 0x70}},
	} {
		t.Run(oid.name, func(t *testing.T) {
			for _, format := range []struct {
				name  string
				value ImportFormat
				wire  string
			}{
				{name: "seed only", wire: "4d2ab6007f480292205f4820" + seedHex},
				{
					name: "with public point", value: ImportFormatStandardWithPublicKey,
					wire: "4d4db6007f4804922099215f4841" + seedHex + "40" + publicHex,
				},
			} {
				t.Run(format.name, func(t *testing.T) {
					want := curve25519ImportHex(t, format.wire)
					defer clear(want)

					got, err := EncodeKeyImport(ControlReferenceTemplate{Tag: DigitalSignatureTemplateTag}, AlgorithmAttributes{
						Algorithm: EdDSA, CurveOID: oid.value, ImportFormat: format.value,
					}, key)
					if err != nil {
						t.Fatal(err)
					}

					if !bytes.Equal(got, want) {
						t.Errorf("Ed25519 key import = %x, want %x", got, want)
					}

					clear(got)

					if !bytes.Equal(key, original) || !bytes.Equal(key.Public().(ed25519.PublicKey), public) {
						t.Error("encoding or clearing the output changed the borrowed Ed25519 key")
					}
				})
			}
		})
	}
}

func TestEd25519KeyImportUnsupportedAttributes(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	defer clear(key)

	for _, test := range []struct {
		name       string
		attributes AlgorithmAttributes
	}{
		{
			name: "unsupported curve",
			attributes: AlgorithmAttributes{
				Algorithm: EdDSA, CurveOID: []byte{0x2b, 0x65, 0x71},
			},
		},
		{
			name: "unsupported import format",
			attributes: AlgorithmAttributes{
				Algorithm: EdDSA, CurveOID: []byte{0x2b, 0x65, 0x70}, ImportFormat: 1,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := EncodeKeyImport(ControlReferenceTemplate{Tag: DigitalSignatureTemplateTag}, test.attributes, key)
			if got != nil || !errors.Is(err, ErrUnsupportedAlgorithm) {
				t.Fatalf("EncodeKeyImport = %x, %v; want nil and unsupported algorithm", got, err)
			}
		})
	}
}

func Test25519KeyImportAlgorithmMismatch(t *testing.T) {
	ed25519Key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	defer clear(ed25519Key)

	x25519Key, err := ecdh.X25519().NewPrivateKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name       string
		attributes AlgorithmAttributes
		key        crypto.PrivateKey
	}{
		{
			name:       "ECDH attributes with Ed25519 key",
			attributes: AlgorithmAttributes{Algorithm: ECDH, CurveOID: []byte{0x2b, 0x65, 0x6e}},
			key:        ed25519Key,
		},
		{
			name:       "EdDSA attributes with X25519 key",
			attributes: AlgorithmAttributes{Algorithm: EdDSA, CurveOID: []byte{0x2b, 0x65, 0x70}},
			key:        x25519Key,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := EncodeKeyImport(ControlReferenceTemplate{Tag: DigitalSignatureTemplateTag}, test.attributes, test.key)
			if got != nil || !errors.Is(err, ErrKeyMismatch) {
				t.Fatalf("EncodeKeyImport = %x, %v; want nil and key mismatch", got, err)
			}
		})
	}
}

func curve25519ImportHex(t testing.TB, encoded string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}

	return decoded
}
