package protocol

import (
	"fmt"
	"slices"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/sign/ed448"
)

// X448PrivateKey is a 56-byte secret in RFC 7748's native little-endian format.
// It is distinct from x448.Key, which ParsePublicKey returns for a public key.
type X448PrivateKey [x448.Size]byte

// Public derives the corresponding native X448 public key.
func (key X448PrivateKey) Public() x448.Key {
	var public x448.Key
	x448.KeyGen(&public, (*x448.Key)(&key))
	clear(key[:])

	return public
}

func x448ImportComponents(attributes AlgorithmAttributes, key X448PrivateKey) ([]keyImportComponent, error) {
	defer clear(key[:])

	if attributes.ImportFormat != ImportFormatStandard && attributes.ImportFormat != ImportFormatStandardWithPublicKey {
		return nil, fmt.Errorf("%w: X448 import format %02x", ErrUnsupportedAlgorithm, attributes.ImportFormat)
	}

	if !isX448OID(attributes.CurveOID) {
		return nil, fmt.Errorf("%w: X448 import curve %x", ErrUnsupportedAlgorithm, attributes.CurveOID)
	}

	// GnuPG's OpenPGP Card implementation imports X448's native secret and
	// public octets directly, unlike legacy Curve25519's scalar and 40 prefix.
	// https://github.com/gpg/gnupg/blob/master/scd/app-openpgp.c
	components := []keyImportComponent{{tag: 0x92, value: slices.Clone(key[:])}}
	if attributes.ImportFormat == ImportFormatStandardWithPublicKey {
		public := key.Public()
		components = append(components, keyImportComponent{tag: 0x99, value: public[:]})
	}

	return components, nil
}

func ed448ImportComponents(attributes AlgorithmAttributes, key ed448.PrivateKey) ([]keyImportComponent, error) {
	if attributes.ImportFormat != ImportFormatStandard && attributes.ImportFormat != ImportFormatStandardWithPublicKey {
		return nil, fmt.Errorf("%w: Ed448 import format %02x", ErrUnsupportedAlgorithm, attributes.ImportFormat)
	}

	if !isEd448OID(attributes.CurveOID) {
		return nil, fmt.Errorf("%w: Ed448 import curve %x", ErrUnsupportedAlgorithm, attributes.CurveOID)
	}

	// Ed448 uses the RFC 8032 seed and raw 57-byte public key, without the
	// legacy Ed25519 40 prefix (GnuPG scd/app-openpgp.c).
	components := []keyImportComponent{{tag: 0x92, value: key.Seed()}}
	if attributes.ImportFormat == ImportFormatStandardWithPublicKey {
		public := key.Public().(ed448.PublicKey)
		components = append(components, keyImportComponent{tag: 0x99, value: public})
	}

	return components, nil
}
