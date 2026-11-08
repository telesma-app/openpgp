package protocol

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/telesma-app/bertlv"
)

// SEC 2, Section 2.4.1: the generator is the public key for private scalar 1.
const secp256k1Generator = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"

func TestSecp256k1PublicAndPrivateKeys(t *testing.T) {
	oid := curve448Hex(t, "2b8104000a")
	point := curve448Hex(t, secp256k1Generator)
	private := ECPrivateKey{CurveOID: oid, Scalar: make([]byte, 32), PublicPoint: point}
	private.Scalar[31] = 1

	for _, algorithm := range []Algorithm{ECDSA, ECDH} {
		attributes := AlgorithmAttributes{Algorithm: algorithm, CurveOID: oid}
		if err := attributes.CheckSupported(); err != nil {
			t.Fatal(err)
		}

		data := bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, point))

		parsed, err := ParsePublicKey(attributes, data)
		if err != nil {
			t.Fatal(err)
		}

		switch key := parsed.(type) {
		case *ecdsa.PublicKey:
			//nolint:staticcheck // secp256k1 has no standard-library key encoding helpers.
			if algorithm != ECDSA || key.Curve != secp256k1.S256() || !bytes.Equal(key.X.Bytes(), point[1:33]) || !bytes.Equal(key.Y.Bytes(), point[33:]) {
				t.Errorf("ECDSA key = %+v", key)
			}
		case ECDHPublicKey:
			if algorithm != ECDH || !bytes.Equal(key.CurveOID, oid) || !bytes.Equal(key.PublicPoint, point) {
				t.Errorf("ECDH key = %+v", key)
			}
		default:
			t.Fatalf("public key type = %T", parsed)
		}

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

				want := append(curve448Hex(t, "4d2ab6007f480292205f4820"), private.Scalar...)
				if format == ImportFormatStandardWithPublicKey {
					want = append(curve448Hex(t, "4d6db6007f4804922099415f4861"), private.Scalar...)
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

func TestSecp256k1RejectsInvalidPublicPoint(t *testing.T) {
	oid := curve448Hex(t, "2b8104000a")

	point := curve448Hex(t, secp256k1Generator)
	for _, algorithm := range []Algorithm{ECDSA, ECDH} {
		for _, invalid := range [][]byte{
			point[:len(point)-1],
			append([]byte{2}, point[1:33]...),
			append([]byte{4}, make([]byte, 64)...),
			append(append([]byte{4}, secp256k1.Params().P.Bytes()...), point[33:]...),
		} {
			data := bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, invalid))
			if _, err := ParsePublicKey(AlgorithmAttributes{Algorithm: algorithm, CurveOID: oid}, data); !errors.Is(err, ErrInvalidResponse) {
				t.Errorf("algorithm %d point %x: error = %v", algorithm, invalid, err)
			}
		}
	}
}
