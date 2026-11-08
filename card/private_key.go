package card

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/telesma-app/openpgp/protocol"
)

// PrivateKey binds a signing slot to its public key and borrows the Device.
// Every signature is checked against that key. Rebind after key replacement
// or an application reset with ActivateFile.
type PrivateKey struct {
	device      *Device
	templateTag protocol.ControlReferenceTemplateTag
	publicKey   crypto.PublicKey
}

// PrivateKey binds the existing RSA, ECDSA, Ed25519 or Ed448 key in SIG, AUT or DEC.
// DEC signing temporarily uses INTERNAL AUTHENTICATE and requires MSE support.
// Reading the key does not establish trust.
func (d *Device) PrivateKey(
	ctx context.Context,
	tag protocol.ControlReferenceTemplateTag,
) (*PrivateKey, error) {
	switch tag {
	case protocol.DigitalSignatureTemplateTag, protocol.AuthenticationTemplateTag, protocol.ConfidentialityTemplateTag:
	default:
		return nil, fmt.Errorf("%w: key %02x cannot sign", protocol.ErrUnsupportedAlgorithm, byte(tag))
	}

	publicKey, err := d.ReadPublicKey(ctx, tag)
	if err != nil {
		return nil, err
	}

	switch publicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, ed448.PublicKey:
	default:
		return nil, fmt.Errorf("%w: signing key type %T", protocol.ErrUnsupportedAlgorithm, publicKey)
	}

	return &PrivateKey{device: d, templateTag: tag, publicKey: publicKey}, nil
}

// Public returns the bound public key without I/O or copying. The returned key
// must not be mutated while bound to PrivateKey.
func (key *PrivateKey) Public() crypto.PublicKey {
	return key.publicKey
}

// Sign signs a SHA-256/384/512 digest with RSA PKCS#1 v1.5 or ECDSA, or an
// Ed25519/Ed448 message with opts.HashFunc() == 0. Ed448 also accepts CIRCL
// SignerOptions selecting ED448 with an empty context. RSA-PSS and prehashed or
// contextual EdDSA are unsupported. The caller handles OpenPGP packets and hashing.
//
// Input preparation precedes AuthenticationSource. VERIFY and signing are atomic;
// nil authentication skips VERIFY. The card supplies entropy. Input and options
// are borrowed. Malformed or unverifiable output returns an error matching
// protocol.ErrInvalidResponse and no signature.
func (key *PrivateKey) Sign(
	ctx context.Context,
	input []byte,
	opts crypto.SignerOpts,
	authentication AuthenticationSource,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	prepared, err := key.prepare(input, opts)
	if err != nil {
		return nil, err
	}

	reference := protocol.PW1
	if key.templateTag == protocol.DigitalSignatureTemplateTag {
		reference = protocol.PW1Sign
	}

	if err := key.device.lockAuthenticated(ctx, reference, authentication); err != nil {
		return nil, err
	}
	defer key.device.unlock()

	var signature []byte
	if key.templateTag == protocol.DigitalSignatureTemplateTag {
		signature, err = key.device.client.ComputeDigitalSignature(ctx, prepared)
	} else {
		signature, err = key.device.withKey(ctx, protocol.AuthenticationTemplateTag, key.templateTag, func() ([]byte, error) {
			return key.device.client.InternalAuthenticate(ctx, prepared)
		})
	}

	if err != nil {
		return nil, key.device.operationError(err)
	}

	return key.verify(input, signature, opts)
}

func (key *PrivateKey) prepare(input []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, ok := key.publicKey.(ed448.PublicKey); ok {
		var options ed448.SignerOptions

		switch value := opts.(type) {
		case crypto.Hash:
		case ed448.SignerOptions:
			options = value
		case *ed448.SignerOptions:
			options = *value
		default:
			return nil, fmt.Errorf("openpgp: unsupported Ed448 signature options %T", opts)
		}

		if options.Context != "" || options.Scheme != ed448.ED448 {
			return nil, fmt.Errorf("openpgp: Ed448 requires the pure scheme with an empty context")
		}

		if opts.HashFunc() != 0 {
			return nil, fmt.Errorf("openpgp: Ed448 requires an unhashed message")
		}

		return input, nil
	}

	if _, ok := key.publicKey.(ed25519.PublicKey); ok {
		switch options := opts.(type) {
		case crypto.Hash:
		case *ed25519.Options:
			if options.Context != "" {
				return nil, fmt.Errorf("openpgp: Ed25519 contexts are unsupported")
			}
		default:
			return nil, fmt.Errorf("openpgp: unsupported Ed25519 signature options %T", opts)
		}

		if opts.HashFunc() != 0 {
			return nil, fmt.Errorf("openpgp: Ed25519 requires an unhashed message")
		}

		return input, nil
	}

	if _, ok := opts.(crypto.Hash); !ok {
		return nil, fmt.Errorf("openpgp: unsupported signature options %T", opts)
	}

	hash := opts.HashFunc()

	var prefix []byte

	switch hash {
	case crypto.SHA256:
		prefix = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
	case crypto.SHA384:
		prefix = []byte{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30}
	case crypto.SHA512:
		prefix = []byte{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}
	default:
		return nil, fmt.Errorf("openpgp: unsupported signature hash %v", hash)
	}

	if len(input) != hash.Size() {
		return nil, fmt.Errorf("openpgp: %v digest must contain %d bytes", hash, hash.Size())
	}

	if publicKey, ok := key.publicKey.(*rsa.PublicKey); ok {
		// The card adds padding; DigestInfo must fit in 40% of the modulus
		// (OpenPGP Card 3.4.1, Secs. 7.2.10 and 7.2.13).
		if (len(prefix)+len(input))*5 > publicKey.Size()*2 {
			return nil, rsa.ErrMessageTooLong
		}

		return append(prefix, input...), nil
	}

	// OpenPGP Card accepts the full digest and truncates it to the curve order
	// (Sec. 7.2.10).
	return input, nil
}

func (key *PrivateKey) verify(input, signature []byte, opts crypto.SignerOpts) ([]byte, error) {
	invalid := func() ([]byte, error) {
		return nil, fmt.Errorf("%w: signature does not match bound public key", protocol.ErrInvalidResponse)
	}

	switch publicKey := key.publicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(publicKey, opts.HashFunc(), input, signature); err != nil {
			return invalid()
		}
	case *ecdsa.PublicKey:
		width := (publicKey.Params().N.BitLen() + 7) / 8
		if len(signature) != 2*width {
			return nil, fmt.Errorf("%w: ECDSA signature length %d, want %d", protocol.ErrInvalidResponse, len(signature), 2*width)
		}

		r := new(big.Int).SetBytes(signature[:width])

		s := new(big.Int).SetBytes(signature[width:])
		if !ecdsa.Verify(publicKey, input, r, s) {
			return invalid()
		}

		return asn1.Marshal(struct{ R, S *big.Int }{R: r, S: s})
	case ed25519.PublicKey:
		if !ed25519.Verify(publicKey, input, signature) {
			return invalid()
		}
	case ed448.PublicKey:
		if !ed448.Verify(publicKey, input, signature, "") {
			return invalid()
		}
	default:
		panic("unsupported bound signing key")
	}

	return signature, nil
}
