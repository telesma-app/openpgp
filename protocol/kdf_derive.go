package protocol

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"slices"
)

// Password derivation follows the salt fields in the KDF DO (Sec. 4.3.2):
// PW1, resetting code, then PW3.

// DerivePW1 derives the value for both PW1 references using PW1Salt.
// Password is borrowed unchanged. The returned buffer is owned by the caller
// and must be cleared after use, including when KDFNone copies the password.
// Unknown KDF or hash algorithms return ErrUnsupportedAlgorithm.
func (k KDF) DerivePW1(password []byte) ([]byte, error) {
	return k.derive(password, k.PW1Salt)
}

// DeriveResettingCode derives the resetting code, using PW1Salt when its
// separate salt is absent. Input and result ownership follow DerivePW1.
func (k KDF) DeriveResettingCode(code []byte) ([]byte, error) {
	salt := k.ResettingCodeSalt
	if salt == nil {
		salt = k.PW1Salt
	}

	return k.derive(code, salt)
}

// DerivePW3 derives the admin password, using PW1Salt when PW3Salt is absent.
// Input and result ownership follow DerivePW1.
func (k KDF) DerivePW3(password []byte) ([]byte, error) {
	salt := k.PW3Salt
	if salt == nil {
		salt = k.PW1Salt
	}

	return k.derive(password, salt)
}

func (k KDF) derive(password, salt []byte) ([]byte, error) {
	switch k.Algorithm {
	case KDFNone:
		return slices.Clone(password), nil
	case KDFIterSaltedS2K:
	default:
		return nil, fmt.Errorf("%w: KDF algorithm %d", ErrUnsupportedAlgorithm, k.Algorithm)
	}

	var h hash.Hash

	switch k.HashAlgorithm {
	case KDFHashSHA256:
		h = sha256.New()
	case KDFHashSHA512:
		h = sha512.New()
	default:
		return nil, fmt.Errorf("%w: KDF hash algorithm %d", ErrUnsupportedAlgorithm, k.HashAlgorithm)
	}

	// RFC 4880, Sec. 3.7.1.3: hash salt || password repeatedly, including a
	// complete first pair even when count is smaller. The card's count is
	// already decoded. Stream it without copying the password or allocating
	// count bytes. uint64 arithmetic also handles the full DO count on 32-bit.
	pairLength := uint64(len(salt)) + uint64(len(password))
	count := max(uint64(k.IterationCount), pairLength)

	for pairs := count / pairLength; pairs != 0; pairs-- {
		h.Write(salt)
		h.Write(password)
	}

	remaining := count % pairLength
	saltBytes := min(remaining, uint64(len(salt)))
	h.Write(salt[:int(saltBytes)])
	h.Write(password[:int(remaining-saltBytes)])

	return h.Sum(nil), nil
}
