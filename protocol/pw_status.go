package protocol

import "fmt"

// Secs. 4.4.1 and 4.4.2: the GET DATA response precedes the PUT DATA update.

// PWStatusBytes is the seven-byte C4 value. PW1Sign and PW1 use the same
// PW1Retries counter. PINBlock2 flags distinguish the format bit from length.
type PWStatusBytes struct {
	PW1ValidForMultipleSignatures bool
	PW1MaxLength                  byte
	ResettingCodeMaxLength        byte
	PW3MaxLength                  byte
	PW1PINBlock2                  bool
	PW3PINBlock2                  bool
	PW1Retries                    byte
	ResettingCodeRetries          byte
	PW3Retries                    byte
}

func ParsePWStatusBytes(data []byte) (PWStatusBytes, error) {
	if len(data) != 7 || data[0] > 1 {
		return PWStatusBytes{}, fmt.Errorf("%w: password status bytes", ErrInvalidResponse)
	}

	return PWStatusBytes{
		PW1ValidForMultipleSignatures: data[0] == 1,
		PW1MaxLength:                  data[1] & 0x7f, ResettingCodeMaxLength: data[2], PW3MaxLength: data[3] & 0x7f,
		PW1PINBlock2: data[1]&0x80 != 0, PW3PINBlock2: data[3]&0x80 != 0,
		PW1Retries: data[4], ResettingCodeRetries: data[5], PW3Retries: data[6],
	}, nil
}

// PWLengthAndFormat is bytes 2-4 of a C4 update (Sec. 4.4.2). PW1MaxLength
// and PW3MaxLength contain the low seven bits; their format bits are separate.
// ResettingCodeMaxLength occupies the complete byte and has no format bit.
// Preserve the card's reported maximum lengths when changing password formats;
// the card controls which updates are supported outside personalisation.
type PWLengthAndFormat struct {
	PW1MaxLength           byte
	ResettingCodeMaxLength byte
	PW3MaxLength           byte
	PW1PINBlock2           bool
	PW3PINBlock2           bool
}

// PWStatusBytesUpdate is the writable C4 data, without retry counters.
// A nil LengthAndFormat sends only the signing-policy byte. A nonnil group
// sends all four bytes, including explicitly supplied zero values.
type PWStatusBytesUpdate struct {
	PW1ValidForMultipleSignatures bool
	LengthAndFormat               *PWLengthAndFormat
}

// EncodePWStatusBytesUpdate returns the one- or four-byte value for PUT DATA C4
// (Sec. 4.4.2). The caller supplies the existing maximum lengths and desired
// format bits; this function does not read or derive them. The result is owned
// by the caller. PWStatusBytes describes the separate seven-byte GET response.
func EncodePWStatusBytesUpdate(update PWStatusBytesUpdate) []byte {
	var policy byte
	if update.PW1ValidForMultipleSignatures {
		policy = 1
	}

	if update.LengthAndFormat == nil {
		return []byte{policy}
	}

	format := update.LengthAndFormat
	data := []byte{policy, format.PW1MaxLength, format.ResettingCodeMaxLength, format.PW3MaxLength}

	if format.PW1PINBlock2 {
		data[1] |= 0x80
	}

	if format.PW3PINBlock2 {
		data[3] |= 0x80
	}

	return data
}
