package protocol

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"
	"slices"
	"testing"

	"github.com/ProtonMail/go-crypto/brainpool"
)

// Independent scalars and points: RFC 8734, Appendix A, party A.
// https://www.rfc-editor.org/rfc/rfc8734#appendix-A
// Import prefixes follow OpenPGP Card 4.4.3.12.
var brainpoolImportVectors = []struct {
	name          string
	curve         elliptic.Curve
	oid           string
	scalar        string
	x             string
	y             string
	privatePrefix string
	publicPrefix  string
}{
	{
		name: "P256r1", curve: brainpool.P256r1(), oid: "2b2403030208010107",
		scalar:        "81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D",
		x:             "44106E913F92BC02A1705D9953A8414DB95E1AAA49E81D9E85F929A8E3100BE5",
		y:             "8AB4846F11CACCB73CE49CBDD120F5A900A69FD32C272223F789EF10EB089BDC",
		privatePrefix: "4d2ab6007f480292205f4820",
		publicPrefix:  "4d6db6007f4804922099415f4861",
	},
	{
		name: "P384r1", curve: brainpool.P384r1(), oid: "2b240303020801010b",
		scalar: `1E20F5E048A5886F1F157C74E91BDE2B98C8B52D58E5003D57053FC4B0BD6
			5D6F15EB5D1EE1610DF870795143627D042`,
		x: `68B665DD91C195800650CDD363C625F4E742E8134667B767B1B47679358
			8F885AB698C852D4A6E77A252D6380FCAF068`,
		y: `55BC91A39C9EC01DEE36017B7D673A931236D2F1F5C83942D049E3FA206
			07493E0D038FF2FD30C2AB67D15C85F7FAA59`,
		privatePrefix: "4d3ab6007f480292305f4830",
		publicPrefix:  "4d819eb6007f4804923099615f488191",
	},
	{
		name: "P512r1", curve: brainpool.P512r1(), oid: "2b240303020801010d",
		scalar: `16302FF0DBBB5A8D733DAB7141C1B45ACBC8715939677F6A56850A38BD87B
			D59B09E80279609FF333EB9D4C061231FB26F92EEB04982A5F1D1764CAD5766542
			2`,
		x: `0A420517E406AAC0ACDCE90FCD71487718D3B953EFD7FBEC5F7F27E28C6
			149999397E91E029E06457DB2D3E640668B392C2A7E737A7F0BF04436D11640FD0
			9FD`,
		y: `72E6882E8DB28AAD36237CD25D580DB23783961C8DC52DFA2EC138AD472
			A0FCEF3887CF62B623B2A87DE5C588301EA3E5FC269B373B60724F5E82A6AD147F
			DE7`,
		privatePrefix: "4d4ab6007f480292405f4840",
		publicPrefix:  "4d81cfb6007f480592409981815f4881c1",
	},
}

//nolint:staticcheck // Brainpool fixtures require raw fields; Go's encoding helpers support only NIST curves.
func TestEncodeBrainpoolKeyImportRFC8734(t *testing.T) {
	for _, vector := range brainpoolImportVectors {
		t.Run(vector.name, func(t *testing.T) {
			key := ECPrivateKey{
				CurveOID:    decodeMultilineHex(t, vector.oid),
				Scalar:      decodeMultilineHex(t, vector.scalar),
				PublicPoint: decodeMultilineHex(t, "04"+vector.x+vector.y),
			}
			before := ECPrivateKey{
				CurveOID: slices.Clone(key.CurveOID), Scalar: slices.Clone(key.Scalar), PublicPoint: slices.Clone(key.PublicPoint),
			}
			goKey := &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: vector.curve,
					X:     new(big.Int).SetBytes(decodeMultilineHex(t, vector.x)),
					Y:     new(big.Int).SetBytes(decodeMultilineHex(t, vector.y)),
				},
				D: new(big.Int).SetBytes(key.Scalar),
			}
			goScalar := goKey.D.Text(16)
			goX, goY := goKey.X.Text(16), goKey.Y.Text(16)

			for _, family := range []struct {
				name      string
				algorithm Algorithm
				key       crypto.PrivateKey
			}{
				{name: "ECDSA protocol key", algorithm: ECDSA, key: key},
				{name: "ECDH protocol key", algorithm: ECDH, key: key},
				{name: "ECDSA Go key", algorithm: ECDSA, key: goKey},
			} {
				t.Run(family.name, func(t *testing.T) {
					for _, format := range []struct {
						name   string
						value  ImportFormat
						prefix string
					}{
						{name: "private only", prefix: vector.privatePrefix},
						{name: "with public point", value: ImportFormatStandardWithPublicKey, prefix: vector.publicPrefix},
					} {
						t.Run(format.name, func(t *testing.T) {
							want := decodeMultilineHex(t, format.prefix+vector.scalar)
							if format.value == ImportFormatStandardWithPublicKey {
								want = append(want, key.PublicPoint...)
							}
							defer clear(want)

							importKey := family.key
							if private, ok := importKey.(ECPrivateKey); ok && format.value == ImportFormatStandard {
								private.PublicPoint = nil
								importKey = private
							}

							got, err := EncodeKeyImport(ControlReferenceTemplate{Tag: DigitalSignatureTemplateTag}, AlgorithmAttributes{
								Algorithm: family.algorithm, CurveOID: key.CurveOID, ImportFormat: format.value,
							}, importKey)
							if err != nil {
								t.Fatal(err)
							}

							if !bytes.Equal(got, want) {
								t.Errorf("key import = %x, want %x", got, want)
							}

							clear(got)

							if !bytes.Equal(key.Scalar, before.Scalar) || !bytes.Equal(key.PublicPoint, before.PublicPoint) || !bytes.Equal(key.CurveOID, before.CurveOID) {
								t.Error("encoding or clearing output changed the borrowed protocol key")
							}

							if goKey.D.Text(16) != goScalar || goKey.X.Text(16) != goX || goKey.Y.Text(16) != goY {
								t.Error("encoding or clearing output changed the borrowed Go key")
							}
						})
					}
				})
			}
		})
	}
}

func TestECKeyImportAttributeAndEncodingMismatch(t *testing.T) {
	vector := brainpoolImportVectors[0]

	key := ECPrivateKey{
		CurveOID: decodeMultilineHex(t, vector.oid), Scalar: decodeMultilineHex(t, vector.scalar),
		PublicPoint: decodeMultilineHex(t, "04"+vector.x+vector.y),
	}
	for _, test := range []struct {
		name       string
		attributes AlgorithmAttributes
		key        ECPrivateKey
		want       error
	}{
		{
			name:       "curve differs",
			attributes: AlgorithmAttributes{Algorithm: ECDH, CurveOID: decodeMultilineHex(t, brainpoolImportVectors[1].oid)},
			key:        key, want: ErrKeyMismatch,
		},
		{
			name:       "unsupported curve",
			attributes: AlgorithmAttributes{Algorithm: ECDH, CurveOID: []byte{0x2b, 0x81, 0x04, 0, 0x09}},
			key:        key, want: ErrUnsupportedAlgorithm,
		},
		{
			name:       "unsupported format",
			attributes: AlgorithmAttributes{Algorithm: ECDSA, CurveOID: key.CurveOID, ImportFormat: 1},
			key:        key, want: ErrUnsupportedAlgorithm,
		},
		{
			name:       "scalar has extra leading byte",
			attributes: AlgorithmAttributes{Algorithm: ECDH, CurveOID: key.CurveOID},
			key: ECPrivateKey{
				CurveOID: key.CurveOID, Scalar: append([]byte{0}, key.Scalar...), PublicPoint: key.PublicPoint,
			},
			want: ErrKeyMismatch,
		},
		{
			name:       "compressed point",
			attributes: AlgorithmAttributes{Algorithm: ECDSA, CurveOID: key.CurveOID, ImportFormat: ImportFormatStandardWithPublicKey},
			key: ECPrivateKey{
				CurveOID: key.CurveOID, Scalar: key.Scalar,
				PublicPoint: append([]byte{2}, decodeMultilineHex(t, vector.x)...),
			},
			want: ErrKeyMismatch,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := EncodeKeyImport(ControlReferenceTemplate{Tag: ConfidentialityTemplateTag}, test.attributes, test.key)
			if got != nil || !errors.Is(err, test.want) {
				t.Fatalf("key import = %x, %v; want nil, %v", got, err, test.want)
			}
		})
	}
}
