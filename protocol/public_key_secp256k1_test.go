package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/telesma-app/bertlv"
)

func TestParseSecp256k1PublicKeys(t *testing.T) {
	oid := decodeHex(t, "2b8104000a")
	point := decodeHex(t, secp256k1Generator)

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
	}
}

func TestSecp256k1RejectsInvalidPublicPoint(t *testing.T) {
	oid := decodeHex(t, "2b8104000a")

	point := decodeHex(t, secp256k1Generator)
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
