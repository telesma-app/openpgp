package protocol

import (
	"crypto/rsa"
	"fmt"
	"math/big"
)

type rsaImportPart struct {
	tag   byte
	value *big.Int
	size  int
}

func rsaImportComponents(attributes AlgorithmAttributes, key *rsa.PrivateKey) ([]keyImportComponent, error) {
	switch attributes.ImportFormat {
	case ImportFormatStandard, ImportFormatStandardWithModulus, ImportFormatCRT, ImportFormatCRTWithModulus:
	default:
		return nil, fmt.Errorf("%w: RSA import format %d", ErrUnsupportedAlgorithm, attributes.ImportFormat)
	}

	if len(key.Primes) > 2 {
		return nil, fmt.Errorf("%w: RSA import requires two primes", ErrUnsupportedAlgorithm)
	}

	if key.N.BitLen() != int(attributes.ModulusBits) {
		return nil, fmt.Errorf("%w: RSA modulus is %d bits, configured %d", ErrKeyMismatch, key.N.BitLen(), attributes.ModulusBits)
	}

	exponent := big.NewInt(int64(key.E))
	if exponent.BitLen() > int(attributes.ExponentBits) {
		return nil, fmt.Errorf("%w: RSA exponent exceeds %d bits", ErrKeyMismatch, attributes.ExponentBits)
	}

	primeSize := (int(attributes.ModulusBits) + 15) / 16

	parts := []rsaImportPart{
		{tag: 0x91, value: exponent, size: (int(attributes.ExponentBits) + 7) / 8},
		{tag: 0x92, value: key.Primes[0], size: primeSize},
		{tag: 0x93, value: key.Primes[1], size: primeSize},
	}
	if attributes.ImportFormat == ImportFormatCRT || attributes.ImportFormat == ImportFormatCRTWithModulus {
		pMinusOne := new(big.Int).Sub(key.Primes[0], big.NewInt(1))
		qMinusOne := new(big.Int).Sub(key.Primes[1], big.NewInt(1))
		qInverse := new(big.Int).ModInverse(key.Primes[1], key.Primes[0])
		dP := new(big.Int).Mod(key.D, pMinusOne)
		dQ := new(big.Int).Mod(key.D, qMinusOne)

		defer func() {
			clear(pMinusOne.Bits())
			clear(qMinusOne.Bits())
			clear(qInverse.Bits())
			clear(dP.Bits())
			clear(dQ.Bits())
		}()

		parts = append(parts,
			rsaImportPart{tag: 0x94, value: qInverse, size: primeSize},
			rsaImportPart{tag: 0x95, value: dP, size: primeSize},
			rsaImportPart{tag: 0x96, value: dQ, size: primeSize},
		)
	}

	if attributes.ImportFormat == ImportFormatStandardWithModulus || attributes.ImportFormat == ImportFormatCRTWithModulus {
		parts = append(parts, rsaImportPart{tag: 0x97, value: key.N, size: (int(attributes.ModulusBits) + 7) / 8})
	}

	for _, part := range parts {
		if part.value.BitLen() > part.size*8 {
			return nil, fmt.Errorf("%w: RSA component %02x exceeds %d bytes", ErrKeyMismatch, part.tag, part.size)
		}
	}

	components := make([]keyImportComponent, len(parts))
	for i, part := range parts {
		components[i] = keyImportComponent{tag: part.tag, value: part.value.FillBytes(make([]byte, part.size))}
	}

	return components, nil
}
