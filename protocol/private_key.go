package protocol

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/telesma-app/bertlv"
)

// EncodeKeyImport encodes the Extended Header List (4D) for PUT DATA
// (Secs. 4.4.3.12 and 7.2.8). Attributes must match the slot's current configuration.
// It accepts two-prime RSA, NIST ECDSA/ECDH, Ed25519 and X25519 Go keys,
// CIRCL ed448.PrivateKey, X448PrivateKey, and ECPrivateKey for NIST, Brainpool
// or secp256k1. Brainpool/secp256k1 ECDSA also accepts *ecdsa.PrivateKey.
// The Yubico/opcard 25519 layouts use an Ed25519 seed and OpenPGP-ordered X25519 scalar.
// Valid keys are borrowed unchanged. Mismatches return ErrKeyMismatch;
// unsupported layouts return ErrUnsupportedAlgorithm.
//
// The caller owns the returned secret buffer and must clear it after use.
// Intermediate buffers are cleared; Go or the transport may retain other copies.
func EncodeKeyImport(
	template ControlReferenceTemplate,
	attributes AlgorithmAttributes,
	key crypto.PrivateKey,
) ([]byte, error) {
	components, err := keyImportComponents(attributes, key)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, component := range components {
			clear(component.value)
		}
	}()

	var (
		headers []byte
		size    int
	)

	for _, component := range components {
		headers = appendKeyImportHeader(headers, component.tag, len(component.value))
		size += len(component.value)
	}

	material := make([]byte, size)
	defer clear(material)

	position := 0
	for _, component := range components {
		position += copy(material[position:], component.value)
	}

	body := bertlv.Append(template.Bytes(), 0x7f48, headers)

	body = bertlv.Append(body, 0x5f48, material)
	defer clear(body)

	return bertlv.Append(nil, 0x4d, body), nil
}

// The receiving encoder owns each component buffer.
type keyImportComponent struct {
	tag   byte
	value []byte
}

func keyImportComponents(attributes AlgorithmAttributes, key crypto.PrivateKey) ([]keyImportComponent, error) {
	switch attributes.Algorithm {
	case RSA:
		private, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: RSA attributes with %T", ErrKeyMismatch, key)
		}

		return rsaImportComponents(attributes, private)
	case ECDSA:
		switch private := key.(type) {
		case ECPrivateKey:
			return ecImportComponents(attributes, private)
		case *ecdsa.PrivateKey:
			return ecdsaImportComponents(attributes, private)
		default:
			return nil, fmt.Errorf("%w: ECDSA attributes with %T", ErrKeyMismatch, key)
		}
	case ECDH:
		switch private := key.(type) {
		case ECPrivateKey:
			return ecImportComponents(attributes, private)
		case *ecdh.PrivateKey:
			return ecdhImportComponents(attributes, private)
		case X448PrivateKey:
			return x448ImportComponents(attributes, private)
		default:
			return nil, fmt.Errorf("%w: ECDH attributes with %T", ErrKeyMismatch, key)
		}
	case EdDSA:
		switch private := key.(type) {
		case ed25519.PrivateKey:
			return ed25519ImportComponents(attributes, private)
		case ed448.PrivateKey:
			return ed448ImportComponents(attributes, private)
		default:
			return nil, fmt.Errorf("%w: EdDSA attributes with %T", ErrKeyMismatch, key)
		}
	default:
		return nil, fmt.Errorf("%w: key import algorithm %d", ErrUnsupportedAlgorithm, attributes.Algorithm)
	}
}

// Component tags are one byte; AlgorithmAttributes' two-byte bit counts bound lengths.
func appendKeyImportHeader(data []byte, tag byte, size int) []byte {
	data = append(data, tag)

	switch {
	case size < 0x80:
		return append(data, byte(size))
	case size <= 0xff:
		return append(data, 0x81, byte(size))
	default:
		return append(data, 0x82, byte(size>>8), byte(size))
	}
}
