package protocol

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/sign/ed448"
)

// ECDHPublicKey represents Brainpool or secp256k1 ECDH, which crypto/ecdh does not support.
// PublicPoint is the DO 86 encoding, 04 || x || y. Both slices borrow parser
// inputs and are read-only. Decipher returns the raw shared secret.
type ECDHPublicKey struct {
	CurveOID    []byte
	PublicPoint []byte
}

// ParsePublicKey decodes a complete 7F49 template matching attributes (Sec. 7.2.14).
// It returns *rsa.PublicKey, *ecdsa.PublicKey, *ecdh.PublicKey, ed25519.PublicKey,
// ed448.PublicKey, x448.Key, or ECDHPublicKey for Brainpool/secp256k1 ECDH.
// RSA exponents above crypto/rsa's 31-bit
// limit return ErrUnsupportedAlgorithm. This is an accepted interoperability
// limit; see README.md. Unknown supplemental fields are ignored.
func ParsePublicKey(attributes AlgorithmAttributes, data []byte) (crypto.PublicKey, error) {
	if err := attributes.CheckSupported(); err != nil {
		return nil, err
	}

	data, err := ParseObject(data, 0x7f49)
	if err != nil {
		return nil, err
	}

	fields, err := objectFields(data)
	if err != nil {
		return nil, err
	}

	if attributes.Algorithm == RSA {
		return parseRSAPublicKey(attributes, fields)
	}

	if _, present := fields[0x81]; present {
		return nil, fmt.Errorf("%w: RSA modulus for an ECC key", ErrInvalidResponse)
	}

	if _, present := fields[0x82]; present {
		return nil, fmt.Errorf("%w: RSA exponent for an ECC key", ErrInvalidResponse)
	}

	point := fields[0x86]

	switch attributes.Algorithm {
	case ECDSA, ECDH:
		if attributes.Algorithm == ECDH && isX25519OID(attributes.CurveOID) {
			key, err := ecdh.X25519().NewPublicKey(point)
			if err != nil {
				return nil, fmt.Errorf("%w: X25519 public key: %v", ErrInvalidResponse, err)
			}

			return key, nil
		}

		if attributes.Algorithm == ECDH && isX448OID(attributes.CurveOID) {
			if len(point) != x448.Size {
				return nil, fmt.Errorf("%w: X448 public key length", ErrInvalidResponse)
			}

			return x448.Key(point), nil
		}

		if curve, dh, ok := nistCurves(attributes.CurveOID); ok {
			if attributes.Algorithm == ECDH {
				key, err := dh.NewPublicKey(point)
				if err != nil {
					return nil, fmt.Errorf("%w: ECDH public key: %v", ErrInvalidResponse, err)
				}

				return key, nil
			}

			key, err := ecdsa.ParseUncompressedPublicKey(curve, point)
			if err != nil {
				return nil, fmt.Errorf("%w: ECDSA public key: %v", ErrInvalidResponse, err)
			}

			return key, nil
		}

		curve, _ := weierstrassCurve(attributes.CurveOID)

		x, y, err := parseECPoint(curve, point)
		if err != nil {
			return nil, err
		}

		if attributes.Algorithm == ECDH {
			return ECDHPublicKey{CurveOID: attributes.CurveOID, PublicPoint: point}, nil
		}

		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil //nolint:staticcheck // Go's encoding helpers do not support Brainpool/secp256k1.
	case EdDSA:
		if isEd448OID(attributes.CurveOID) {
			if len(point) != ed448.PublicKeySize {
				return nil, fmt.Errorf("%w: Ed448 public key length", ErrInvalidResponse)
			}

			return ed448.PublicKey(point), nil
		}

		if len(point) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: Ed25519 public key length", ErrInvalidResponse)
		}

		return ed25519.PublicKey(point), nil
	default:
		return nil, fmt.Errorf("%w: public key algorithm %d", ErrUnsupportedAlgorithm, attributes.Algorithm)
	}
}

func parseRSAPublicKey(attributes AlgorithmAttributes, fields map[uint32][]byte) (*rsa.PublicKey, error) {
	modulus, exponent := fields[0x81], fields[0x82]
	if _, present := fields[0x86]; present {
		return nil, fmt.Errorf("%w: ECC point for an RSA key", ErrInvalidResponse)
	}

	if len(modulus) != (int(attributes.ModulusBits)+7)/8 {
		return nil, fmt.Errorf("%w: RSA modulus length", ErrInvalidResponse)
	}

	n := new(big.Int).SetBytes(modulus)
	if n.BitLen() != int(attributes.ModulusBits) || n.Bit(0) == 0 {
		return nil, fmt.Errorf("%w: RSA modulus", ErrInvalidResponse)
	}

	for len(exponent) != 0 && exponent[0] == 0 {
		exponent = exponent[1:]
	}

	if len(exponent) == 0 {
		return nil, fmt.Errorf("%w: RSA public exponent length", ErrInvalidResponse)
	}

	e := new(big.Int).SetBytes(exponent)
	if e.BitLen() > int(attributes.ExponentBits) || e.Cmp(big.NewInt(3)) < 0 || e.Bit(0) == 0 {
		return nil, fmt.Errorf("%w: RSA public exponent", ErrInvalidResponse)
	}

	if e.BitLen() > 31 {
		return nil, fmt.Errorf("%w: RSA public exponent exceeds crypto/rsa's 31-bit limit", ErrUnsupportedAlgorithm)
	}

	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}
