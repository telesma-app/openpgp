package protocol

import (
	"encoding/binary"
	"fmt"
	"math/bits"

	"github.com/telesma-app/bertlv"
)

// KDFAlgorithm is the algorithm byte in the KDF DO (Sec. 4.3.2).
type KDFAlgorithm byte

const (
	KDFNone          KDFAlgorithm = 0
	KDFIterSaltedS2K KDFAlgorithm = 3
)

// KDFHashAlgorithm uses the OpenPGP hash IDs from the KDF DO, not crypto.Hash IDs.
type KDFHashAlgorithm byte

const (
	KDFHashSHA256 KDFHashAlgorithm = 8
	KDFHashSHA512 KDFHashAlgorithm = 10
)

// KDF contains password derivation parameters and initial password hashes from
// DO F9 (Sec. 4.3.2). The zero value selects untransformed UTF-8 passwords.
// IterationCount counts bytes hashed, not hash rounds. Iterated S2K requires
// an eight-byte PW1Salt; absent ResettingCodeSalt and PW3Salt use PW1Salt.
// Nil slices indicate absent optional fields. Raw and parsed slices borrow
// the response. Initial hashes are metadata, not inputs to derivation.
type KDF struct {
	Raw               []byte
	Algorithm         KDFAlgorithm
	HashAlgorithm     KDFHashAlgorithm
	IterationCount    uint32
	PW1Salt           []byte
	ResettingCodeSalt []byte
	PW3Salt           []byte
	InitialPW1Hash    []byte
	InitialPW3Hash    []byte
}

// ParseKDF accepts the complete F9 template or its child DOs. Empty data denotes
// KDFNone. Malformed data returns ErrInvalidResponse; unknown algorithm IDs are
// retained. Applying the specification's UTF-8 fallback for invalid or unsupported
// KDF data is the caller's decision; derivation never silently selects plaintext.
func ParseKDF(data []byte) (KDF, error) {
	raw := data

	data, err := constructedContents(data, 0xf9)
	if err != nil {
		return KDF{}, err
	}

	if len(data) == 0 {
		return KDF{Raw: raw}, nil
	}

	fields, err := objectFields(data)
	if err != nil {
		return KDF{}, err
	}

	algorithm := fields[0x81]
	if len(algorithm) != 1 {
		return KDF{}, fmt.Errorf("%w: KDF algorithm length", ErrInvalidResponse)
	}

	kdf := KDF{
		Raw: raw, Algorithm: KDFAlgorithm(algorithm[0]),
		PW1Salt: fields[0x84], ResettingCodeSalt: fields[0x85], PW3Salt: fields[0x86],
		InitialPW1Hash: fields[0x87], InitialPW3Hash: fields[0x88],
	}

	if value, present := fields[0x82]; present {
		if len(value) != 1 {
			return KDF{}, fmt.Errorf("%w: KDF hash algorithm length", ErrInvalidResponse)
		}

		kdf.HashAlgorithm = KDFHashAlgorithm(value[0])
	}

	if value, present := fields[0x83]; present {
		if len(value) != 4 {
			return KDF{}, fmt.Errorf("%w: KDF iteration count length", ErrInvalidResponse)
		}

		kdf.IterationCount = binary.BigEndian.Uint32(value)
	}

	for _, salt := range [][]byte{kdf.PW1Salt, kdf.ResettingCodeSalt, kdf.PW3Salt} {
		if salt != nil && len(salt) != 8 {
			return KDF{}, fmt.Errorf("%w: KDF salt length", ErrInvalidResponse)
		}
	}

	if kdf.Algorithm == KDFIterSaltedS2K {
		_, hashPresent := fields[0x82]
		_, countPresent := fields[0x83]

		if !hashPresent || !countPresent || kdf.PW1Salt == nil {
			return KDF{}, fmt.Errorf("%w: incomplete iterated-salted KDF parameters", ErrInvalidResponse)
		}

		var hashSize int

		switch kdf.HashAlgorithm {
		case KDFHashSHA256:
			hashSize = 32
		case KDFHashSHA512:
			hashSize = 64
		}

		for _, initial := range [][]byte{kdf.InitialPW1Hash, kdf.InitialPW3Hash} {
			if hashSize != 0 && initial != nil && len(initial) != hashSize {
				return KDF{}, fmt.Errorf("%w: KDF initial password hash length", ErrInvalidResponse)
			}
		}
	}

	return kdf, nil
}

// EncodeKDF returns child DOs for PUT DATA F9, without an outer F9 template.
// Zero optional numeric values are omitted for KDFNone and unknown algorithms;
// iterated S2K always includes its hash and count, including a zero count.
// Raw and unknown fields are not encoded. The caller owns the returned buffer,
// which may contain initial password hashes, and must clear it after use.
func EncodeKDF(kdf KDF) []byte {
	fields := []struct {
		tag   uint32
		value []byte
	}{
		{0x84, kdf.PW1Salt},
		{0x85, kdf.ResettingCodeSalt},
		{0x86, kdf.PW3Salt},
		{0x87, kdf.InitialPW1Hash},
		{0x88, kdf.InitialPW3Hash},
	}

	// Reserve the three numeric DOs and all slice fields before copying any
	// initial passwords, so reallocation cannot leave uncleared secret copies.
	size := 12

	for _, field := range fields {
		if field.value != nil {
			size += 2 + len(field.value)
			if len(field.value) >= 0x80 {
				size += (bits.Len(uint(len(field.value))) + 7) / 8
			}
		}
	}

	data := bertlv.Append(make([]byte, 0, size), 0x81, []byte{byte(kdf.Algorithm)})
	if kdf.Algorithm == KDFIterSaltedS2K || kdf.HashAlgorithm != 0 {
		data = bertlv.Append(data, 0x82, []byte{byte(kdf.HashAlgorithm)})
	}

	if kdf.Algorithm == KDFIterSaltedS2K || kdf.IterationCount != 0 {
		var count [4]byte
		binary.BigEndian.PutUint32(count[:], kdf.IterationCount)
		data = bertlv.Append(data, 0x83, count[:])
	}

	for _, field := range fields {
		if field.value != nil {
			data = bertlv.Append(data, field.tag, field.value)
		}
	}

	return data
}
