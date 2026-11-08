package protocol_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/openpgp/protocol"
)

func TestParseRSAPublicKey(t *testing.T) {
	attributes := protocol.AlgorithmAttributes{Algorithm: protocol.RSA, ModulusBits: 2048, ExponentBits: 32}
	modulus := make([]byte, 256)
	modulus[0], modulus[255] = 0x80, 1
	data := bertlv.Append(nil, 0x81, modulus)
	data = bertlv.Append(data, 0x82, []byte{0, 1, 0, 1})
	// Supplemental ISO 7816-8 fields are allowed by Sec. 7.2.14.
	data = bertlv.Append(data, 0x83, []byte{1, 2})

	parsed, err := protocol.ParsePublicKey(attributes, bertlv.Append(nil, 0x7f49, data))
	if err != nil {
		t.Fatal(err)
	}

	key, ok := parsed.(*rsa.PublicKey)
	if !ok || key.E != 65537 || !bytes.Equal(key.N.Bytes(), modulus) {
		t.Errorf("public key = %#v", parsed)
	}
}

func TestParseNISTPublicKeys(t *testing.T) {
	for _, tc := range []struct {
		name  string
		curve elliptic.Curve
		dh    ecdh.Curve
		oid   []byte
	}{
		{"P256", elliptic.P256(), ecdh.P256(), []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7}},
		{"P384", elliptic.P384(), ecdh.P384(), []byte{0x2b, 0x81, 4, 0, 0x22}},
		{"P521", elliptic.P521(), ecdh.P521(), []byte{0x2b, 0x81, 4, 0, 0x23}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scalar := make([]byte, (tc.curve.Params().BitSize+7)/8)
			scalar[len(scalar)-1] = 1

			private, err := tc.dh.NewPrivateKey(scalar)
			if err != nil {
				t.Fatal(err)
			}

			point := private.PublicKey().Bytes()

			data := bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, point))
			for _, algorithm := range []protocol.Algorithm{protocol.ECDSA, protocol.ECDH} {
				parsed, err := protocol.ParsePublicKey(protocol.AlgorithmAttributes{Algorithm: algorithm, CurveOID: tc.oid}, data)
				if err != nil {
					t.Fatal(err)
				}

				switch key := parsed.(type) {
				case *ecdsa.PublicKey:
					encoded, err := key.Bytes()
					if err != nil {
						t.Fatal(err)
					}

					if algorithm != protocol.ECDSA || key.Curve != tc.curve || !bytes.Equal(encoded, point) {
						t.Errorf("ECDSA key = %+v", key)
					}
				case *ecdh.PublicKey:
					if algorithm != protocol.ECDH || key.Curve() != tc.dh || !bytes.Equal(key.Bytes(), point) {
						t.Errorf("ECDH key = %+v", key)
					}
				default:
					t.Errorf("key type = %T", parsed)
				}
			}
		})
	}
}

func TestParse25519PublicKeys(t *testing.T) {
	public := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	for _, oid := range [][]byte{{0x2b, 0x06, 1, 4, 1, 0xda, 0x47, 0x0f, 1}, {0x2b, 0x65, 0x70}} {
		parsed, err := protocol.ParsePublicKey(
			protocol.AlgorithmAttributes{Algorithm: protocol.EdDSA, CurveOID: oid},
			bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, public)),
		)
		if err != nil {
			t.Fatal(err)
		}

		key, ok := parsed.(ed25519.PublicKey)
		if !ok || !bytes.Equal(key, public) {
			t.Errorf("Ed25519 key = %#v", parsed)
		}
	}

	for _, oid := range [][]byte{{0x2b, 0x06, 1, 4, 1, 0x97, 0x55, 1, 5, 1}, {0x2b, 0x65, 0x6e}} {
		point := make([]byte, 32)
		point[0] = 9

		parsed, err := protocol.ParsePublicKey(
			protocol.AlgorithmAttributes{Algorithm: protocol.ECDH, CurveOID: oid},
			bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, point)),
		)
		if err != nil {
			t.Fatal(err)
		}

		key, ok := parsed.(*ecdh.PublicKey)
		if !ok || key.Curve() != ecdh.X25519() || !bytes.Equal(key.Bytes(), point) {
			t.Errorf("X25519 key = %#v", parsed)
		}
	}
}

func TestParsePublicKeyMalformed(t *testing.T) {
	rsaAttributes := protocol.AlgorithmAttributes{Algorithm: protocol.RSA, ModulusBits: 2048, ExponentBits: 32}
	modulus := make([]byte, 256)
	modulus[0], modulus[255] = 0x80, 1
	modulusDO := bertlv.Append(nil, 0x81, modulus)

	validRSA := bertlv.Append(bytes.Clone(modulusDO), 0x82, []byte{1, 0, 1})
	for name, fields := range map[string][]byte{
		"missing exponent":  modulusDO,
		"exponent one":      bertlv.Append(bytes.Clone(modulusDO), 0x82, []byte{1}),
		"exponent two":      bertlv.Append(bytes.Clone(modulusDO), 0x82, []byte{2}),
		"even exponent":     bertlv.Append(bytes.Clone(modulusDO), 0x82, []byte{4}),
		"exponent width":    bertlv.Append(bytes.Clone(modulusDO), 0x82, []byte{1, 0, 0, 0, 1}),
		"duplicate modulus": bertlv.Append(bytes.Clone(validRSA), 0x81, modulus),
		"mixed ECC":         bertlv.Append(bytes.Clone(validRSA), 0x86, []byte{4}),
		"truncated modulus": {0x81, 3, 0, 1},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := protocol.ParsePublicKey(rsaAttributes, bertlv.Append(nil, 0x7f49, fields))
			if !errors.Is(err, protocol.ErrInvalidResponse) {
				t.Errorf("error = %v", err)
			}
		})
	}

	point := make([]byte, 65)
	point[0] = 4

	_, err := protocol.ParsePublicKey(
		protocol.AlgorithmAttributes{Algorithm: protocol.ECDSA, CurveOID: []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7}},
		bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, point)),
	)
	if !errors.Is(err, protocol.ErrInvalidResponse) {
		t.Errorf("off-curve error = %v", err)
	}
}

func TestParseRSAPublicKeyRejectsUnsupportedExponent(t *testing.T) {
	attributes := protocol.AlgorithmAttributes{Algorithm: protocol.RSA, ModulusBits: 2048, ExponentBits: 32}
	modulus := make([]byte, 256)
	modulus[0], modulus[len(modulus)-1] = 0x80, 1
	data := bertlv.Append(nil, 0x81, modulus)
	data = bertlv.Append(data, 0x82, []byte{0x80, 0, 0, 1})

	_, err := protocol.ParsePublicKey(attributes, bertlv.Append(nil, 0x7f49, data))
	if !errors.Is(err, protocol.ErrUnsupportedAlgorithm) || errors.Is(err, protocol.ErrInvalidResponse) {
		t.Errorf("large RSA exponent error = %v; want unsupported Go RSA exponent", err)
	}
}
