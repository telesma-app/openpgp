package protocol

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"slices"
	"testing"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/telesma-app/bertlv"
)

// RFC 8032, Section 7.4, Ed448's one-octet test, and RFC 7748, Section 6.2,
// Alice's X448 key pair. Card import octets follow GnuPG scd/app-openpgp.c:
// 448 secrets and public keys retain their native encoding, without a 40 prefix.
const (
	ed448Seed  = "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e"
	ed448Point = "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480"
	x448Secret = "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"
	x448Point  = "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
)

func curve448Hex(t testing.TB, value string) []byte {
	t.Helper()

	data, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func TestParse448PublicKeys(t *testing.T) {
	for _, test := range []struct {
		name      string
		algorithm Algorithm
		oid       string
		point     string
	}{
		{name: "Ed448", algorithm: EdDSA, oid: "2b6571", point: ed448Point},
		{name: "X448", algorithm: ECDH, oid: "2b656f", point: x448Point},
	} {
		t.Run(test.name, func(t *testing.T) {
			attributes, err := ParseAlgorithmAttributes(curve448Hex(t, hex.EncodeToString([]byte{byte(test.algorithm)})+test.oid+"ff"))
			if err != nil {
				t.Fatal(err)
			}

			if err := attributes.CheckSupported(); err != nil {
				t.Fatal(err)
			}

			point := curve448Hex(t, test.point)
			data := bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, point))

			parsed, err := ParsePublicKey(attributes, data)
			if err != nil {
				t.Fatal(err)
			}

			switch key := parsed.(type) {
			case ed448.PublicKey:
				if test.algorithm != EdDSA || !bytes.Equal(key, point) {
					t.Errorf("Ed448 public key = %x", key)
				}
			case x448.Key:
				if test.algorithm != ECDH || !bytes.Equal(key[:], point) {
					t.Errorf("X448 public key = %x", key)
				}
			default:
				t.Fatalf("public key type = %T", parsed)
			}

			for _, invalid := range [][]byte{point[:len(point)-1], append([]byte{0x40}, point...), append(slices.Clone(point), 0)} {
				data := bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, invalid))
				if _, err := ParsePublicKey(attributes, data); !errors.Is(err, ErrInvalidResponse) {
					t.Errorf("public key size %d: error = %v", len(invalid), err)
				}
			}
		})
	}
}

func Test448KeyImportRFCVectors(t *testing.T) {
	xSecret := X448PrivateKey(curve448Hex(t, x448Secret))
	xBefore := xSecret

	xPublic := xSecret.Public()
	if !bytes.Equal(xPublic[:], curve448Hex(t, x448Point)) || xSecret != xBefore {
		t.Fatal("X448 public derivation does not match RFC 7748 or changed the borrowed secret")
	}

	edPrivate := ed448.NewKeyFromSeed(curve448Hex(t, ed448Seed))
	defer clear(edPrivate)

	edBefore := slices.Clone(edPrivate)
	defer clear(edBefore)

	for _, test := range []struct {
		name           string
		algorithm      Algorithm
		oid            string
		tag            ControlReferenceTemplateTag
		key            crypto.PrivateKey
		secret         string
		point          string
		standardPrefix string
		publicPrefix   string
	}{
		{name: "Ed448", algorithm: EdDSA, oid: "2b6571", tag: DigitalSignatureTemplateTag, key: edPrivate,
			secret: ed448Seed, point: ed448Point, standardPrefix: "4d43b6007f480292395f4839", publicPrefix: "4d7eb6007f4804923999395f4872"},
		{name: "X448", algorithm: ECDH, oid: "2b656f", tag: ConfidentialityTemplateTag, key: xSecret,
			secret: x448Secret, point: x448Point, standardPrefix: "4d42b8007f480292385f4838", publicPrefix: "4d7cb8007f4804923899385f4870"},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, format := range []ImportFormat{ImportFormatStandard, ImportFormatStandardWithPublicKey} {
				attributes := AlgorithmAttributes{Algorithm: test.algorithm, CurveOID: curve448Hex(t, test.oid), ImportFormat: format}

				wantHex := test.standardPrefix + test.secret
				if format == ImportFormatStandardWithPublicKey {
					wantHex = test.publicPrefix + test.secret + test.point
				}

				got, err := EncodeKeyImport(ControlReferenceTemplate{Tag: test.tag}, attributes, test.key)
				if err != nil {
					t.Fatal(err)
				}

				if !bytes.Equal(got, curve448Hex(t, wantHex)) {
					t.Errorf("format %02x import = %x, want %s", format, got, wantHex)
				}

				clear(got)
			}
		})
	}

	if !bytes.Equal(edPrivate, edBefore) || xSecret != xBefore {
		t.Error("encoding or clearing imports changed borrowed key material")
	}
}

func Test448KeyImportMismatch(t *testing.T) {
	edPrivate := ed448.NewKeyFromSeed(curve448Hex(t, ed448Seed))
	defer clear(edPrivate)

	xPrivate := X448PrivateKey(curve448Hex(t, x448Secret))
	for _, test := range []struct {
		name       string
		attributes AlgorithmAttributes
		key        crypto.PrivateKey
		want       error
	}{
		{name: "Ed448 format", attributes: AlgorithmAttributes{Algorithm: EdDSA, CurveOID: curve448Hex(t, "2b6571"), ImportFormat: 1}, key: edPrivate, want: ErrUnsupportedAlgorithm},
		{name: "X448 format", attributes: AlgorithmAttributes{Algorithm: ECDH, CurveOID: curve448Hex(t, "2b656f"), ImportFormat: 1}, key: xPrivate, want: ErrUnsupportedAlgorithm},
		{name: "Ed448 curve", attributes: AlgorithmAttributes{Algorithm: EdDSA, CurveOID: curve448Hex(t, "2b6570")}, key: edPrivate, want: ErrUnsupportedAlgorithm},
		{name: "X448 curve", attributes: AlgorithmAttributes{Algorithm: ECDH, CurveOID: curve448Hex(t, "2b656e")}, key: xPrivate, want: ErrUnsupportedAlgorithm},
		{name: "Ed448 algorithm", attributes: AlgorithmAttributes{Algorithm: ECDH, CurveOID: curve448Hex(t, "2b656f")}, key: edPrivate, want: ErrKeyMismatch},
		{name: "X448 algorithm", attributes: AlgorithmAttributes{Algorithm: EdDSA, CurveOID: curve448Hex(t, "2b6571")}, key: xPrivate, want: ErrKeyMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := EncodeKeyImport(ControlReferenceTemplate{Tag: DigitalSignatureTemplateTag}, test.attributes, test.key)
			if got != nil || !errors.Is(err, test.want) {
				t.Fatalf("import = %x, %v; want nil, %v", got, err, test.want)
			}
		})
	}
}
