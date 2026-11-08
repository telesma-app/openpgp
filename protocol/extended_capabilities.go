package protocol

import (
	"encoding/binary"
	"fmt"
)

// SecureMessagingAlgorithm is byte 2 of Extended Capabilities (Sec. 4.4.3.7).
// Zero means no secure messaging when its capability bit is clear, or a
// proprietary implementation when the bit is set.
type SecureMessagingAlgorithm byte

const (
	SecureMessagingNoneOrProprietary SecureMessagingAlgorithm = 0
	SecureMessagingAES128            SecureMessagingAlgorithm = 1
	SecureMessagingAES256            SecureMessagingAlgorithm = 2
	SecureMessagingSCP11b            SecureMessagingAlgorithm = 3
)

// ExtendedCapabilities is the ten-byte C0 value for version 3.x (Sec. 4.4.3.7).
// These are reported capabilities, not authenticated evidence.
type ExtendedCapabilities struct {
	Raw                           []byte
	SecureMessaging               bool
	GetChallenge                  bool
	KeyImport                     bool
	PWStatusBytesChangeable       bool
	PrivateUseObjects             bool
	AlgorithmAttributesChangeable bool
	AES                           bool
	KDF                           bool
	SecureMessagingAlgorithm      SecureMessagingAlgorithm
	MaxChallengeLength            uint16
	MaxCertificateLength          uint16
	MaxSpecialObjectLength        uint16
	PINBlock2                     bool
	ManageSecurityEnvironment     bool
}

func ParseExtendedCapabilities(data []byte) (ExtendedCapabilities, error) {
	if len(data) != 10 {
		return ExtendedCapabilities{}, fmt.Errorf("%w: extended capabilities length", ErrInvalidResponse)
	}

	return ExtendedCapabilities{
		Raw:             data,
		SecureMessaging: data[0]&0x80 != 0, GetChallenge: data[0]&0x40 != 0,
		KeyImport: data[0]&0x20 != 0, PWStatusBytesChangeable: data[0]&0x10 != 0,
		PrivateUseObjects: data[0]&0x08 != 0, AlgorithmAttributesChangeable: data[0]&0x04 != 0,
		AES: data[0]&0x02 != 0, KDF: data[0]&0x01 != 0,
		SecureMessagingAlgorithm: SecureMessagingAlgorithm(data[1]),
		MaxChallengeLength:       binary.BigEndian.Uint16(data[2:4]),
		MaxCertificateLength:     binary.BigEndian.Uint16(data[4:6]),
		MaxSpecialObjectLength:   binary.BigEndian.Uint16(data[6:8]),
		PINBlock2:                data[8] == 1, ManageSecurityEnvironment: data[9] == 1,
	}, nil
}
