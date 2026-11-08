package protocol

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/ProtonMail/go-crypto/brainpool"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Secs. 4.4.3.10 and 10: supported elliptic curves and their wire representations.

func nistCurves(oid []byte) (elliptic.Curve, ecdh.Curve, bool) {
	switch string(oid) {
	case "\x2a\x86\x48\xce\x3d\x03\x01\x07": // 1.2.840.10045.3.1.7
		return elliptic.P256(), ecdh.P256(), true
	case "\x2b\x81\x04\x00\x22": // 1.3.132.0.34
		return elliptic.P384(), ecdh.P384(), true
	case "\x2b\x81\x04\x00\x23": // 1.3.132.0.35
		return elliptic.P521(), ecdh.P521(), true
	default:
		return nil, nil, false
	}
}

func weierstrassCurve(oid []byte) (elliptic.Curve, bool) {
	if curve, _, ok := nistCurves(oid); ok {
		return curve, true
	}

	switch string(oid) {
	case "\x2b\x81\x04\x00\x0a": // 1.3.132.0.10
		return secp256k1.S256(), true //nolint:staticcheck // The public ECDSA key API represents secp256k1 with elliptic.Curve.
	case "\x2b\x24\x03\x03\x02\x08\x01\x01\x07": // 1.3.36.3.3.2.8.1.1.7
		return brainpool.P256r1(), true
	case "\x2b\x24\x03\x03\x02\x08\x01\x01\x0b": // 1.3.36.3.3.2.8.1.1.11
		return brainpool.P384r1(), true
	case "\x2b\x24\x03\x03\x02\x08\x01\x01\x0d": // 1.3.36.3.3.2.8.1.1.13
		return brainpool.P512r1(), true
	default:
		return nil, false
	}
}

// parseECPoint decodes DO 86 (Sec. 7.2.14), checking canonical coordinates
// before IsOnCurve, since some implementations reduce them modulo p.
func parseECPoint(curve elliptic.Curve, point []byte) (*big.Int, *big.Int, error) {
	width := (curve.Params().BitSize + 7) / 8
	if len(point) != 1+2*width || point[0] != 4 {
		return nil, nil, fmt.Errorf("%w: uncompressed EC point encoding", ErrInvalidResponse)
	}

	x := new(big.Int).SetBytes(point[1 : 1+width])
	y := new(big.Int).SetBytes(point[1+width:])

	if x.Cmp(curve.Params().P) >= 0 || y.Cmp(curve.Params().P) >= 0 || !curve.IsOnCurve(x, y) { //nolint:staticcheck // Brainpool/secp256k1 have no crypto/ecdh implementation.
		return nil, nil, fmt.Errorf("%w: EC point is not on the curve", ErrInvalidResponse)
	}

	return x, y, nil
}

func isX25519OID(oid []byte) bool {
	// OpenPGP's legacy Curve25519 OID and the RFC 8410 X25519 OID.
	return string(oid) == "\x2b\x06\x01\x04\x01\x97\x55\x01\x05\x01" || string(oid) == "\x2b\x65\x6e"
}

func isX448OID(oid []byte) bool {
	return string(oid) == "\x2b\x65\x6f" // 1.3.101.111 (RFC 8410).
}

func isEd25519OID(oid []byte) bool {
	// OpenPGP's legacy Ed25519 OID and the RFC 8410 Ed25519 OID.
	return string(oid) == "\x2b\x06\x01\x04\x01\xda\x47\x0f\x01" || string(oid) == "\x2b\x65\x70"
}

func isEd448OID(oid []byte) bool {
	return string(oid) == "\x2b\x65\x71" // 1.3.101.113 (RFC 8410).
}
