package protocol

import (
	"encoding/binary"
	"fmt"
)

// Secs. 4.4.3.9-4.4.3.10: algorithm attributes and supported algorithms.

// Algorithm identifies the public-key algorithm in an algorithm attributes DO.
type Algorithm byte

const (
	RSA   Algorithm = 1
	ECDSA Algorithm = 19
	ECDH  Algorithm = 18
	EdDSA Algorithm = 22
)

// ImportFormat selects the private-key layout in Algorithm Attributes
// (Sec. 4.4.3.9). Standard is e, p, q for RSA and a private key without a
// public key for EC; EC encodes that choice by omitting the format byte.
// Formats 01-03 apply to RSA only; FF applies to EC only.
type ImportFormat byte

const (
	ImportFormatStandard              ImportFormat = 0
	ImportFormatStandardWithModulus   ImportFormat = 1
	ImportFormatCRT                   ImportFormat = 2
	ImportFormatCRTWithModulus        ImportFormat = 3
	ImportFormatStandardWithPublicKey ImportFormat = 0xff
)

// AlgorithmAttributes describes a slot's current algorithm, retaining unknown IDs.
// Raw and CurveOID borrow the parsed response.
type AlgorithmAttributes struct {
	Algorithm    Algorithm
	ModulusBits  uint16
	ExponentBits uint16
	ImportFormat ImportFormat
	CurveOID     []byte
	Raw          []byte
}

// ParseAlgorithmAttributes parses a C1, C2, or C3 value (Sec. 4.4.3.9).
func ParseAlgorithmAttributes(data []byte) (AlgorithmAttributes, error) {
	if len(data) == 0 {
		return AlgorithmAttributes{}, fmt.Errorf("%w: empty algorithm attributes", ErrInvalidResponse)
	}

	attributes := AlgorithmAttributes{Algorithm: Algorithm(data[0]), Raw: data}
	switch attributes.Algorithm {
	case RSA:
		if len(data) != 6 {
			return AlgorithmAttributes{}, fmt.Errorf("%w: RSA algorithm attributes length", ErrInvalidResponse)
		}

		attributes.ModulusBits = binary.BigEndian.Uint16(data[1:3])
		attributes.ExponentBits = binary.BigEndian.Uint16(data[3:5])

		attributes.ImportFormat = ImportFormat(data[5])
		if attributes.ModulusBits == 0 || attributes.ExponentBits == 0 || attributes.ImportFormat > ImportFormatCRTWithModulus {
			return AlgorithmAttributes{}, fmt.Errorf("%w: RSA algorithm attributes", ErrInvalidResponse)
		}
	case ECDH, ECDSA, EdDSA:
		oid := data[1:]
		if len(oid) != 0 && oid[len(oid)-1] == byte(ImportFormatStandardWithPublicKey) {
			attributes.ImportFormat = ImportFormatStandardWithPublicKey
			oid = oid[:len(oid)-1]
		}

		if !validOID(oid) {
			return AlgorithmAttributes{}, fmt.Errorf("%w: elliptic curve OID", ErrInvalidResponse)
		}

		attributes.CurveOID = oid
	}

	return attributes, nil
}

// EncodeAlgorithmAttributes returns the value for PUT DATA, without its object
// tag or length (Sec. 4.4.3.9). Known algorithms use the typed fields, ignoring
// Raw. Unknown algorithms require a complete Raw value; their opaque payload
// is retained. Attributes must describe a valid configuration. The returned
// buffer is owned by the caller and does not alias Raw or CurveOID.
func EncodeAlgorithmAttributes(attributes AlgorithmAttributes) []byte {
	switch attributes.Algorithm {
	case RSA:
		data := make([]byte, 6)
		data[0] = byte(attributes.Algorithm)
		binary.BigEndian.PutUint16(data[1:3], attributes.ModulusBits)
		binary.BigEndian.PutUint16(data[3:5], attributes.ExponentBits)
		data[5] = byte(attributes.ImportFormat)

		return data
	case ECDH, ECDSA, EdDSA:
		data := make([]byte, 1, len(attributes.CurveOID)+2)
		data[0] = byte(attributes.Algorithm)

		data = append(data, attributes.CurveOID...)
		if attributes.ImportFormat != ImportFormatStandard {
			data = append(data, byte(attributes.ImportFormat))
		}

		return data
	default:
		return append([]byte{byte(attributes.Algorithm)}, attributes.Raw[1:]...)
	}
}

// CheckSupported checks local support for the algorithms in Sec. 4.4.3.10,
// not the card's generation capabilities.
// Call it before generation to reject unsupported formats before key replacement.
func (a AlgorithmAttributes) CheckSupported() error {
	switch a.Algorithm {
	case RSA:
		return nil
	case ECDH:
		if isX25519OID(a.CurveOID) || isX448OID(a.CurveOID) {
			return nil
		}

		if _, ok := weierstrassCurve(a.CurveOID); ok {
			return nil
		}
	case ECDSA:
		if _, ok := weierstrassCurve(a.CurveOID); ok {
			return nil
		}
	case EdDSA:
		if isEd25519OID(a.CurveOID) || isEd448OID(a.CurveOID) {
			return nil
		}
	}

	return fmt.Errorf("%w: algorithm %d curve %x", ErrUnsupportedAlgorithm, a.Algorithm, a.CurveOID)
}

func validOID(oid []byte) bool {
	if len(oid) == 0 || oid[len(oid)-1]&0x80 != 0 {
		return false
	}
	// An OID subidentifier cannot start with a redundant zero group.
	start := true
	for _, b := range oid {
		if start && b == 0x80 {
			return false
		}

		start = b&0x80 == 0
	}

	return true
}
