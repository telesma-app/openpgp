package protocol

import (
	"bytes"
	"fmt"

	"github.com/telesma-app/bertlv"
)

// Object identifies a data object addressed by GET DATA or PUT DATA.
type Object uint16

const (
	// Sec. 4.4.1: DOs for GET DATA, in first-appearance order.
	PrivateUse1Object Object = 0x0101
	PrivateUse2Object Object = 0x0102
	PrivateUse3Object Object = 0x0103
	PrivateUse4Object Object = 0x0104

	ApplicationIdentifierObject Object = 0x4f
	LoginDataObject             Object = 0x5e
	URLObject                   Object = 0x5f50
	HistoricalBytesObject       Object = 0x5f52

	CardholderRelatedDataObject Object = 0x65
	NameObject                  Object = 0x5b
	LanguagePreferencesObject   Object = 0x5f2d
	SexObject                   Object = 0x5f35

	ApplicationRelatedDataObject    Object = 0x6e
	ExtendedLengthInformationObject Object = 0x7f66
	GeneralFeatureManagementObject  Object = 0x7f74

	ExtendedCapabilitiesObject              Object = 0xc0
	SignatureAlgorithmAttributesObject      Object = 0xc1
	DecryptionAlgorithmAttributesObject     Object = 0xc2
	AuthenticationAlgorithmAttributesObject Object = 0xc3
	PWStatusBytesObject                     Object = 0xc4
	FingerprintsObject                      Object = 0xc5
	CAFingerprintsObject                    Object = 0xc6
	KeyGenerationTimesObject                Object = 0xcd
	KeyInformationObject                    Object = 0xde
	SignatureUIFObject                      Object = 0xd6
	DecryptionUIFObject                     Object = 0xd7
	AuthenticationUIFObject                 Object = 0xd8

	// Reserved for Yubico attestation (Secs. 4.4.1 and 4.4.2).
	AttestationUIFObject Object = 0xd9

	SecuritySupportTemplateObject Object = 0x7a
	CardholderCertificateObject   Object = 0x7f21

	// Reserved for Yubico attestation (Secs. 4.4.1 and 4.4.2).
	AttestationAlgorithmAttributesObject Object = 0xda
	AttestationFingerprintObject         Object = 0xdb
	AttestationCAFingerprintObject       Object = 0xdc
	AttestationKeyGenerationTimeObject   Object = 0xdd

	KDFObject                  Object = 0xf9
	AlgorithmInformationObject Object = 0xfa

	// SMCertificateObject is reserved for secure messaging certificates, such
	// as those used with SCP11b (Secs. 4.4.1 and 4.4.2).
	SMCertificateObject Object = 0xfb

	// AttestationCertificateObject is reserved for Yubico attestation
	// certificates (Secs. 4.4.1 and 4.4.2).
	AttestationCertificateObject Object = 0xfc

	// Sec. 4.4.2: additional DOs for PUT DATA.
	SignatureFingerprintObject            Object = 0xc7
	DecryptionFingerprintObject           Object = 0xc8
	AuthenticationFingerprintObject       Object = 0xc9
	CAFingerprint1Object                  Object = 0xca
	CAFingerprint2Object                  Object = 0xcb
	CAFingerprint3Object                  Object = 0xcc
	SignatureKeyGenerationTimeObject      Object = 0xce
	DecryptionKeyGenerationTimeObject     Object = 0xcf
	AuthenticationKeyGenerationTimeObject Object = 0xd0
	SMKeyENCObject                        Object = 0xd1
	SMKeyMACObject                        Object = 0xd2
	ResettingCodeObject                   Object = 0xd3
	AESKeyObject                          Object = 0xd5
	SMKeyContainerObject                  Object = 0xf4
)

// ParseObject unwraps exactly one BER-TLV object with the expected wire tag.
func ParseObject(data []byte, expected uint32) ([]byte, error) {
	tag, value, rest, err := bertlv.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	if tag != expected || len(rest) != 0 {
		return nil, fmt.Errorf("%w: expected sole tag %x", ErrInvalidResponse, expected)
	}

	return value, nil
}

// Accept both the Sec. 7.2.6 child-DO
// sequence and the complete templates returned by YubiKey and TOKEN2 applets.
func constructedContents(data []byte, expected uint16) ([]byte, error) {
	tag := [2]byte{byte(expected >> 8), byte(expected)}
	prefix := tag[:]

	if expected <= 0xff {
		prefix = prefix[1:]
	}

	if bytes.HasPrefix(data, prefix) {
		return ParseObject(data, uint32(expected))
	}

	return data, nil
}

// objectFields retains unknown fields and rejects malformed TLVs or duplicates.
func objectFields(data []byte) (map[uint32][]byte, error) {
	fields := make(map[uint32][]byte)

	for len(data) != 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
		}

		if _, exists := fields[tag]; exists {
			return nil, fmt.Errorf("%w: duplicate tag %x", ErrInvalidResponse, tag)
		}

		fields[tag] = value
		data = rest
	}

	return fields, nil
}
