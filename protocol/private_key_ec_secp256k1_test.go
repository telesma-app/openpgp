package protocol

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestEncodeSecp256k1KeyImport(t *testing.T) {
	oid := decodeHex(t, "2b8104000a")
	point := decodeHex(t, secp256k1Generator)
	private := ECPrivateKey{CurveOID: oid, Scalar: make([]byte, 32), PublicPoint: point}
	private.Scalar[31] = 1

	for _, algorithm := range []Algorithm{ECDSA, ECDH} {
		attributes := AlgorithmAttributes{Algorithm: algorithm, CurveOID: oid}

		keys := []crypto.PrivateKey{private}
		if algorithm == ECDSA {
			//nolint:staticcheck // secp256k1 imports use the generic elliptic.Curve representation.
			keys = append(keys, &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{
				Curve: secp256k1.S256(), X: new(big.Int).SetBytes(point[1:33]), Y: new(big.Int).SetBytes(point[33:]),
			}, D: big.NewInt(1)})
		}

		for _, key := range keys {
			for _, format := range []ImportFormat{ImportFormatStandard, ImportFormatStandardWithPublicKey} {
				attributes.ImportFormat = format

				want := append(decodeHex(t, "4d2ab6007f480292205f4820"), private.Scalar...)
				if format == ImportFormatStandardWithPublicKey {
					want = append(decodeHex(t, "4d6db6007f4804922099415f4861"), private.Scalar...)
					want = append(want, point...)
				}

				got, err := EncodeKeyImport(ControlReferenceTemplate{Tag: DigitalSignatureTemplateTag}, attributes, key)
				if err != nil {
					t.Fatal(err)
				}

				if !bytes.Equal(got, want) {
					t.Errorf("algorithm %d format %02x import = %x, want %x", algorithm, format, got, want)
				}

				clear(got)
				clear(want)
			}
		}
	}
}
