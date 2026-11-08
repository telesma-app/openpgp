package protocol

import (
	"crypto/ed25519"
	"fmt"
)

func ed25519ImportComponents(attributes AlgorithmAttributes, key ed25519.PrivateKey) ([]keyImportComponent, error) {
	if attributes.ImportFormat != ImportFormatStandard && attributes.ImportFormat != ImportFormatStandardWithPublicKey {
		return nil, fmt.Errorf("%w: Ed25519 import format %02x", ErrUnsupportedAlgorithm, attributes.ImportFormat)
	}

	if !isEd25519OID(attributes.CurveOID) {
		return nil, fmt.Errorf("%w: Ed25519 import curve %x", ErrUnsupportedAlgorithm, attributes.CurveOID)
	}

	// OpenPGP imports the RFC 8032 seed, without reversing or expanding it.
	// https://developers.yubico.com/yubikey-manager/API_Documentation/_modules/yubikit/openpgp.html
	components := []keyImportComponent{{tag: 0x92, value: key.Seed()}}
	if attributes.ImportFormat == ImportFormatStandardWithPublicKey {
		// Opcard's FF import layout includes the 40 native-point prefix.
		// https://github.com/Nitrokey/opcard-rs/blob/v1.10.0/src/types.rs
		public := append([]byte{0x40}, key.Public().(ed25519.PublicKey)...)
		components = append(components, keyImportComponent{tag: 0x99, value: public})
	}

	return components, nil
}
