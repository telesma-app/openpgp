package protocol

import "errors"

// EncodePINBlock2 encodes four to twelve ASCII decimal digits in the eight-byte
// ISO 9564 PIN block format 2 (Secs. 4.3.3 and 7.2.2). The format nibble is 2,
// followed by the binary PIN length, packed decimal digits and F filler nibbles.
// The caller and card enforce the password role's minimum length: six digits
// for PW1, eight for PW3 and the resetting code, and any card-specific maximum.
// The returned block contains the PIN; clear it after its last use.
func EncodePINBlock2(pin string) ([8]byte, error) {
	if len(pin) < 4 || len(pin) > 12 {
		return [8]byte{}, errors.New("openpgp: PIN block format 2 requires four to twelve ASCII digits")
	}

	for i := range len(pin) {
		if pin[i] < '0' || pin[i] > '9' {
			return [8]byte{}, errors.New("openpgp: PIN block format 2 requires four to twelve ASCII digits")
		}
	}

	encoded := [8]byte{0x20 | byte(len(pin)), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	for i := 0; i < len(pin); i += 2 {
		encoded[1+i/2] = (pin[i]-'0')<<4 | 0x0f
		if i+1 < len(pin) {
			encoded[1+i/2] = encoded[1+i/2]&0xf0 | (pin[i+1] - '0')
		}
	}

	return encoded, nil
}
