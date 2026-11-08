package protocol

import (
	"encoding/binary"
	"fmt"

	"github.com/telesma-app/bertlv"
)

// ExtendedLengthInformation contains the maximum total command and response
// APDU lengths, including secure messaging (Sec. 4.1.3.1). Raw borrows the
// response. Lengths retain the reported values without selecting an encoding
// or applying the specification's short-APDU default.
type ExtendedLengthInformation struct {
	Raw                   []byte
	MaxCommandAPDULength  uint16
	MaxResponseAPDULength uint16
}

// ParseExtendedLengthInformation accepts the complete 7F66 template or its
// child DOs. The two INTEGER values have the same tag: command length comes
// first, followed by response length. Unknown child DOs remain in Raw.
func ParseExtendedLengthInformation(data []byte) (ExtendedLengthInformation, error) {
	raw := data

	data, err := constructedContents(data, 0x7f66)
	if err != nil {
		return ExtendedLengthInformation{}, err
	}

	var (
		lengths [2]uint16
		found   int
	)

	for len(data) != 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return ExtendedLengthInformation{}, fmt.Errorf("%w: extended length information: %v", ErrInvalidResponse, err)
		}

		if tag == 0x02 {
			if len(value) != 2 || found == len(lengths) {
				return ExtendedLengthInformation{}, fmt.Errorf("%w: extended length INTEGER", ErrInvalidResponse)
			}

			lengths[found] = binary.BigEndian.Uint16(value)
			found++
		}

		data = rest
	}

	if found != len(lengths) {
		return ExtendedLengthInformation{}, fmt.Errorf("%w: incomplete extended length information", ErrInvalidResponse)
	}

	return ExtendedLengthInformation{
		Raw: raw, MaxCommandAPDULength: lengths[0], MaxResponseAPDULength: lengths[1],
	}, nil
}
