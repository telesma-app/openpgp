package protocol_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"
	"testing"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/openpgp/protocol"
)

// Independent public points from RFC 8734, Appendix A.1-A.3, party A.
// https://www.rfc-editor.org/rfc/rfc8734.html#appendix-A
var brainpoolPublicKeyVectors = []struct {
	name string
	oid  string
	x    string
	y    string
}{
	{
		name: "brainpoolP256r1", oid: "2b2403030208010107",
		x: "44106e913f92bc02a1705d9953a8414db95e1aaa49e81d9e85f929a8e3100be5",
		y: "8ab4846f11caccb73ce49cbdd120f5a900a69fd32c272223f789ef10eb089bdc",
	},
	{
		name: "brainpoolP384r1", oid: "2b240303020801010b",
		x: "68b665dd91c195800650cdd363c625f4e742e8134667b767b1b476793588f885ab698c852d4a6e77a252d6380fcaf068",
		y: "55bc91a39c9ec01dee36017b7d673a931236d2f1f5c83942d049e3fa20607493e0d038ff2fd30c2ab67d15c85f7faa59",
	},
	{
		name: "brainpoolP512r1", oid: "2b240303020801010d",
		x: "0a420517e406aac0acdce90fcd71487718d3b953efd7fbec5f7f27e28c6149999397e91e029e06457db2d3e640668b392c2a7e737a7f0bf04436d11640fd09fd",
		y: "72e6882e8db28aad36237cd25d580db23783961c8dc52dfa2ec138ad472a0fcef3887cf62b623b2a87de5c588301ea3e5fc269b373b60724f5e82a6ad147fde7",
	},
}

func TestParseBrainpoolPublicKeys(t *testing.T) {
	for _, vector := range brainpoolPublicKeyVectors {
		t.Run(vector.name, func(t *testing.T) {
			oid := decodeHex(t, vector.oid)
			point := decodeHex(t, "04"+vector.x+vector.y)
			data := bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, point))

			for _, tc := range []struct {
				name      string
				algorithm protocol.Algorithm
			}{
				{name: "ECDSA", algorithm: protocol.ECDSA},
				{name: "ECDH", algorithm: protocol.ECDH},
			} {
				t.Run(tc.name, func(t *testing.T) {
					attributes := protocol.AlgorithmAttributes{Algorithm: tc.algorithm, CurveOID: oid}
					if err := attributes.CheckSupported(); err != nil {
						t.Fatal(err)
					}

					parsed, err := protocol.ParsePublicKey(attributes, data)
					if err != nil {
						t.Fatal(err)
					}

					switch tc.algorithm {
					case protocol.ECDSA:
						key, ok := parsed.(*ecdsa.PublicKey)
						if !ok {
							t.Fatalf("Brainpool ECDSA key = %T", parsed)
						}
						//nolint:staticcheck // Go's ECDSA key encoding methods do not support Brainpool curves.
						if key.Curve.Params().Name != vector.name || !bytes.Equal(elliptic.Marshal(key.Curve, key.X, key.Y), point) {
							t.Errorf("Brainpool ECDSA key = %+v", key)
						}
					case protocol.ECDH:
						key, ok := parsed.(protocol.ECDHPublicKey)
						if !ok {
							t.Fatalf("Brainpool ECDH key = %T", parsed)
						}

						if !bytes.Equal(key.CurveOID, oid) || !bytes.Equal(key.PublicPoint, point) {
							t.Errorf("Brainpool ECDH key = %+v", key)
						}

						if &key.PublicPoint[0] != &data[len(data)-len(point)] || &key.CurveOID[0] != &oid[0] {
							t.Error("Brainpool ECDH fields do not borrow their input")
						}
					}
				})
			}
		})
	}
}

func TestParseBrainpoolPublicKeyRejectsInvalidPoint(t *testing.T) {
	for _, vector := range brainpoolPublicKeyVectors {
		t.Run(vector.name, func(t *testing.T) {
			point := decodeHex(t, "04"+vector.x+vector.y)
			offCurve := make([]byte, len(point))
			offCurve[0] = 4
			wrongPrefix := bytes.Clone(point)
			wrongPrefix[0] = 2

			for name, invalid := range map[string][]byte{
				"off curve": offCurve,
				"width":     point[:len(point)-1],
				"prefix":    wrongPrefix,
			} {
				t.Run(name, func(t *testing.T) {
					for _, algorithm := range []protocol.Algorithm{protocol.ECDSA, protocol.ECDH} {
						_, err := protocol.ParsePublicKey(protocol.AlgorithmAttributes{
							Algorithm: algorithm, CurveOID: decodeHex(t, vector.oid),
						}, bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, invalid)))
						if !errors.Is(err, protocol.ErrInvalidResponse) {
							t.Errorf("invalid Brainpool point: error = %v", err)
						}
					}
				})
			}
		})
	}
}

func TestParseBrainpoolPublicKeyRejectsNoncanonicalCoordinates(t *testing.T) {
	// RFC 5639, Sec. 3.4: Gy + P fits in 32 bytes but is noncanonical.
	// IsOnCurve's coordinate reduction must not make this encoding acceptable.
	point := decodeHex(t, "048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997")
	p := new(big.Int).SetBytes(decodeHex(t, "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377"))
	y := new(big.Int).SetBytes(point[33:])
	y.Add(y, p)
	y.FillBytes(point[33:])

	for _, algorithm := range []protocol.Algorithm{protocol.ECDSA, protocol.ECDH} {
		_, err := protocol.ParsePublicKey(protocol.AlgorithmAttributes{
			Algorithm: algorithm, CurveOID: decodeHex(t, "2b2403030208010107"),
		}, bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, point)))
		if !errors.Is(err, protocol.ErrInvalidResponse) {
			t.Errorf("noncanonical Brainpool coordinate: error = %v", err)
		}
	}
}
