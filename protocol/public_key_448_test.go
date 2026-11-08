package protocol

import (
	"bytes"
	"encoding/hex"
	"errors"
	"slices"
	"testing"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/telesma-app/bertlv"
)

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
			attributes, err := ParseAlgorithmAttributes(decodeHex(t, hex.EncodeToString([]byte{byte(test.algorithm)})+test.oid+"ff"))
			if err != nil {
				t.Fatal(err)
			}

			if err := attributes.CheckSupported(); err != nil {
				t.Fatal(err)
			}

			point := decodeHex(t, test.point)
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
