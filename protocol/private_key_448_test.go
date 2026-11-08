package protocol

import (
	"bytes"
	"crypto"
	"errors"
	"slices"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
)

func Test448KeyImportRFCVectors(t *testing.T) {
	xSecret := X448PrivateKey(decodeHex(t, x448Secret))
	xBefore := xSecret

	xPublic := xSecret.Public()
	if !bytes.Equal(xPublic[:], decodeHex(t, x448Point)) || xSecret != xBefore {
		t.Fatal("X448 public derivation does not match RFC 7748 or changed the borrowed secret")
	}

	edPrivate := ed448.NewKeyFromSeed(decodeHex(t, ed448Seed))
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
				attributes := AlgorithmAttributes{Algorithm: test.algorithm, CurveOID: decodeHex(t, test.oid), ImportFormat: format}

				wantHex := test.standardPrefix + test.secret
				if format == ImportFormatStandardWithPublicKey {
					wantHex = test.publicPrefix + test.secret + test.point
				}

				got, err := EncodeKeyImport(ControlReferenceTemplate{Tag: test.tag}, attributes, test.key)
				if err != nil {
					t.Fatal(err)
				}

				if !bytes.Equal(got, decodeHex(t, wantHex)) {
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
	edPrivate := ed448.NewKeyFromSeed(decodeHex(t, ed448Seed))
	defer clear(edPrivate)

	xPrivate := X448PrivateKey(decodeHex(t, x448Secret))
	for _, test := range []struct {
		name       string
		attributes AlgorithmAttributes
		key        crypto.PrivateKey
		want       error
	}{
		{name: "Ed448 format", attributes: AlgorithmAttributes{Algorithm: EdDSA, CurveOID: decodeHex(t, "2b6571"), ImportFormat: 1}, key: edPrivate, want: ErrUnsupportedAlgorithm},
		{name: "X448 format", attributes: AlgorithmAttributes{Algorithm: ECDH, CurveOID: decodeHex(t, "2b656f"), ImportFormat: 1}, key: xPrivate, want: ErrUnsupportedAlgorithm},
		{name: "Ed448 curve", attributes: AlgorithmAttributes{Algorithm: EdDSA, CurveOID: decodeHex(t, "2b6570")}, key: edPrivate, want: ErrUnsupportedAlgorithm},
		{name: "X448 curve", attributes: AlgorithmAttributes{Algorithm: ECDH, CurveOID: decodeHex(t, "2b656e")}, key: xPrivate, want: ErrUnsupportedAlgorithm},
		{name: "Ed448 algorithm", attributes: AlgorithmAttributes{Algorithm: ECDH, CurveOID: decodeHex(t, "2b656f")}, key: edPrivate, want: ErrKeyMismatch},
		{name: "X448 algorithm", attributes: AlgorithmAttributes{Algorithm: EdDSA, CurveOID: decodeHex(t, "2b6571")}, key: xPrivate, want: ErrKeyMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := EncodeKeyImport(ControlReferenceTemplate{Tag: DigitalSignatureTemplateTag}, test.attributes, test.key)
			if got != nil || !errors.Is(err, test.want) {
				t.Fatalf("import = %x, %v; want nil, %v", got, err, test.want)
			}
		})
	}
}
