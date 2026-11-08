package protocol

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"fmt"
	"slices"
)

// ECPrivateKey is a NIST, Brainpool or secp256k1 ECDSA/ECDH import key (Sec. 4.4.3.12).
// Scalar is big-endian, padded to the curve's field size. PublicPoint is the
// matching 04 || X || Y point, required for format FF and ignored for format 00.
// The caller ensures key validity and scalar/point agreement; encoding does no
// scalar multiplication. All slices are borrowed unchanged.
type ECPrivateKey struct {
	CurveOID    []byte
	Scalar      []byte
	PublicPoint []byte
}

func ecImportComponents(attributes AlgorithmAttributes, key ECPrivateKey) ([]keyImportComponent, error) {
	if attributes.ImportFormat != ImportFormatStandard && attributes.ImportFormat != ImportFormatStandardWithPublicKey {
		return nil, fmt.Errorf("%w: EC import format %02x", ErrUnsupportedAlgorithm, attributes.ImportFormat)
	}

	curve, ok := weierstrassCurve(attributes.CurveOID)
	if !ok {
		return nil, fmt.Errorf("%w: EC import curve %x", ErrUnsupportedAlgorithm, attributes.CurveOID)
	}

	if !bytes.Equal(key.CurveOID, attributes.CurveOID) {
		return nil, fmt.Errorf("%w: EC curve differs from %x", ErrKeyMismatch, attributes.CurveOID)
	}

	width := (curve.Params().BitSize + 7) / 8
	if len(key.Scalar) != width {
		return nil, fmt.Errorf("%w: EC private scalar length %d, want %d", ErrKeyMismatch, len(key.Scalar), width)
	}

	if attributes.ImportFormat == ImportFormatStandardWithPublicKey && (len(key.PublicPoint) != 1+2*width || key.PublicPoint[0] != 4) {
		return nil, fmt.Errorf("%w: EC public point encoding", ErrKeyMismatch)
	}

	components := []keyImportComponent{{tag: 0x92, value: slices.Clone(key.Scalar)}}
	if attributes.ImportFormat == ImportFormatStandardWithPublicKey {
		components = append(components, keyImportComponent{tag: 0x99, value: slices.Clone(key.PublicPoint)})
	}

	return components, nil
}

//nolint:staticcheck // Brainpool/secp256k1 require raw key fields; Go's encoding helpers support only NIST curves.
func ecdsaImportComponents(attributes AlgorithmAttributes, key *ecdsa.PrivateKey) ([]keyImportComponent, error) {
	if attributes.ImportFormat != ImportFormatStandard && attributes.ImportFormat != ImportFormatStandardWithPublicKey {
		return nil, fmt.Errorf("%w: ECDSA import format %02x", ErrUnsupportedAlgorithm, attributes.ImportFormat)
	}

	curve, ok := weierstrassCurve(attributes.CurveOID)
	if !ok {
		return nil, fmt.Errorf("%w: ECDSA import curve %x", ErrUnsupportedAlgorithm, attributes.CurveOID)
	}

	if key.Curve != curve {
		return nil, fmt.Errorf("%w: ECDSA curve differs from %x", ErrKeyMismatch, attributes.CurveOID)
	}

	if _, _, nist := nistCurves(attributes.CurveOID); !nist {
		width := (curve.Params().BitSize + 7) / 8

		components := []keyImportComponent{{tag: 0x92, value: key.D.FillBytes(make([]byte, width))}}
		if attributes.ImportFormat == ImportFormatStandardWithPublicKey {
			public := make([]byte, 1+2*width)
			public[0] = 4
			key.X.FillBytes(public[1 : 1+width])
			key.Y.FillBytes(public[1+width:])
			components = append(components, keyImportComponent{tag: 0x99, value: public})
		}

		return components, nil
	}

	private, err := key.Bytes()
	if err != nil {
		return nil, err
	}

	components := []keyImportComponent{{tag: 0x92, value: private}}

	if attributes.ImportFormat == ImportFormatStandardWithPublicKey {
		public, err := key.PublicKey.Bytes()
		if err != nil {
			clear(private)
			return nil, err
		}

		components = append(components, keyImportComponent{tag: 0x99, value: public})
	}

	return components, nil
}

func ecdhImportComponents(attributes AlgorithmAttributes, key *ecdh.PrivateKey) ([]keyImportComponent, error) {
	if attributes.ImportFormat != ImportFormatStandard && attributes.ImportFormat != ImportFormatStandardWithPublicKey {
		return nil, fmt.Errorf("%w: ECDH import format %02x", ErrUnsupportedAlgorithm, attributes.ImportFormat)
	}

	if isX25519OID(attributes.CurveOID) {
		if key.Curve() != ecdh.X25519() {
			return nil, fmt.Errorf("%w: ECDH key is not X25519", ErrKeyMismatch)
		}
		// OpenPGP import uses big-endian X25519 private material, while
		// crypto/ecdh exposes the RFC 7748 little-endian encoding.
		// https://developers.yubico.com/yubikey-manager/API_Documentation/_modules/yubikit/openpgp.html
		private := key.Bytes()
		slices.Reverse(private)
		components := []keyImportComponent{{tag: 0x92, value: private}}

		if attributes.ImportFormat == ImportFormatStandardWithPublicKey {
			// The OpenPGP import point includes the 40 native-point prefix.
			// https://github.com/Nitrokey/opcard-rs/blob/v1.10.0/src/types.rs
			public := append([]byte{0x40}, key.PublicKey().Bytes()...)
			components = append(components, keyImportComponent{tag: 0x99, value: public})
		}

		return components, nil
	}

	_, curve, ok := nistCurves(attributes.CurveOID)
	if !ok {
		return nil, fmt.Errorf("%w: ECDH import curve %x", ErrUnsupportedAlgorithm, attributes.CurveOID)
	}

	if key.Curve() != curve {
		return nil, fmt.Errorf("%w: ECDH curve differs from %x", ErrKeyMismatch, attributes.CurveOID)
	}

	components := []keyImportComponent{{tag: 0x92, value: key.Bytes()}}
	if attributes.ImportFormat == ImportFormatStandardWithPublicKey {
		components = append(components, keyImportComponent{tag: 0x99, value: key.PublicKey().Bytes()})
	}

	return components, nil
}
