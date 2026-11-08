package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// ApplicationIdentifier identifies an OpenPGP card (Sec. 4.2.1).
// Versions retain BCD encoding; SerialNumber is the manufacturer's serial number.
// SerialNumber alone is not globally unique.
type ApplicationIdentifier struct {
	Raw          [16]byte
	VersionMajor byte
	VersionMinor byte
	Manufacturer uint16
	SerialNumber uint32
}

func ParseApplicationIdentifier(data []byte) (ApplicationIdentifier, error) {
	if len(data) != 16 || !bytes.Equal(data[:6], []byte{0xd2, 0x76, 0x00, 0x01, 0x24, 0x01}) {
		return ApplicationIdentifier{}, fmt.Errorf("%w: OpenPGP application identifier", ErrInvalidResponse)
	}

	return ApplicationIdentifier{
		Raw: [16]byte(data), VersionMajor: data[6], VersionMinor: data[7],
		Manufacturer: binary.BigEndian.Uint16(data[8:10]),
		SerialNumber: binary.BigEndian.Uint32(data[10:14]),
	}, nil
}

func (a ApplicationIdentifier) String() string {
	return fmt.Sprintf("%X", a.Raw)
}
