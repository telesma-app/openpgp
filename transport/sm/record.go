// Command protection followed by response verification and decryption (Sec. 7.5).
package sm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
	"slices"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

type recordSession struct {
	enc       cipher.Block
	mac       cipher.Block
	encoding  iso7816.Encoding
	macLength int
	keys      Keys
}

func newRecordSession(keys Keys, encoding iso7816.Encoding, macLength int) (recordSession, error) {
	if encoding != iso7816.EncodingShort && encoding != iso7816.EncodingExtended {
		return recordSession{}, fmt.Errorf("sm: select short or extended APDU encoding explicitly")
	}

	if macLength == 0 {
		macLength = 8
	}

	if macLength != 8 && macLength != 16 {
		return recordSession{}, fmt.Errorf("sm: MAC length must be 8 or 16 bytes")
	}

	if (len(keys.ENC) != 16 && len(keys.ENC) != 32) || len(keys.MAC) != len(keys.ENC) {
		return recordSession{}, fmt.Errorf("sm: ENC and MAC keys must both contain 16 or 32 bytes")
	}

	enc, err := aes.NewCipher(keys.ENC)
	if err != nil {
		return recordSession{}, err
	}

	mac, err := aes.NewCipher(keys.MAC)
	if err != nil {
		return recordSession{}, err
	}

	return recordSession{
		enc: enc, mac: mac, encoding: encoding, macLength: macLength,
		keys: Keys{ENC: slices.Clone(keys.ENC), MAC: slices.Clone(keys.MAC)},
	}, nil
}

// plainCommand identifies OpenPGP commands defined only for CLA 00.
func plainCommand(instruction byte) bool {
	switch protocol.Instruction(instruction) {
	case protocol.Select, protocol.SelectData, protocol.PerformSecurityOperation,
		protocol.InternalAuthenticate, protocol.GetChallenge, protocol.ManageSecurityEnvironment:
		return true
	default:
		return false
	}
}

func (s *recordSession) validateCommand(command iso7816.Command) error {
	if command.CLA != 0 {
		return fmt.Errorf("%w: unsupported OpenPGP SM CLA %02x", iso7816.ErrInvalidCommand, command.CLA)
	}

	switch command.Encoding {
	case iso7816.EncodingAuto, iso7816.EncodingExtended:
	case iso7816.EncodingShort:
		if command.Le > 256 {
			return fmt.Errorf("%w: short command Le exceeds 256", iso7816.ErrInvalidCommand)
		}
	default:
		return fmt.Errorf("%w: unsupported command encoding", iso7816.ErrInvalidCommand)
	}

	if len(command.Data) > 65535 || command.Le > 65536 {
		return fmt.Errorf("%w: OpenPGP command exceeds ISO 7816 length limits", iso7816.ErrInvalidCommand)
	}

	if plainCommand(command.INS) {
		return nil
	}

	switch protocol.Instruction(command.INS) {
	case protocol.Verify, protocol.ChangeReferenceData, protocol.ResetRetryCounter,
		protocol.GetData, protocol.GetDataOdd, protocol.GetNextData, protocol.PutData,
		protocol.PutDataOdd, protocol.GenerateAsymmetricKeyPair, protocol.TerminateDF,
		protocol.ActivateFile:
	case 0xc0: // GET RESPONSE (OpenPGP Card 3.4.1, Sec. 7.2.9).
	default:
		return fmt.Errorf("%w: unsupported OpenPGP SM instruction %02x", iso7816.ErrInvalidCommand, command.INS)
	}

	size := objectSize(s.macLength)

	if len(command.Data) != 0 {
		encrypted := (len(command.Data)/aes.BlockSize + 1) * aes.BlockSize
		if command.INS&1 == 0 {
			encrypted++ // DO 87's padding indicator.
		}

		size += objectSize(encrypted)
	}

	if command.Le != 0 {
		size += objectSize(len(commandLe(command)))
	}

	if size > 65535 {
		return fmt.Errorf("%w: protected OpenPGP command exceeds 65535 bytes", iso7816.ErrInvalidCommand)
	}

	_, _, err := s.keyChange(command)

	return err
}

// protect receives an SM command checked by validateCommand before challenge I/O.
func (s *recordSession) protect(command iso7816.Command, rnd [aes.BlockSize]byte) iso7816.Command {
	var data []byte

	if len(command.Data) != 0 {
		encrypted := encrypt(s.enc, rnd, command.Data)
		if command.INS&1 == 0 {
			data = bertlv.Append(data, 0x87, append([]byte{1}, encrypted...))
		} else {
			data = bertlv.Append(data, 0x85, encrypted)
		}
	}

	if command.Le != 0 {
		data = bertlv.Append(data, 0x97, commandLe(command))
	}

	command.CLA = 0x0c
	// Sec. 7.5, p. 83: pad header and body separately. An absent body adds no
	// padding block. ISO padding makes CMAC use K1 for the final block.
	macInput := pad([]byte{command.CLA, command.INS, command.P1, command.P2})
	if len(data) != 0 {
		macInput = append(macInput, pad(data)...)
	}

	mac := cmac(s.mac, rnd, macInput)
	command.Data = bertlv.Append(data, 0x8e, mac[:s.macLength])
	command.Encoding = s.encoding
	command.Le = 256

	if s.encoding == iso7816.EncodingExtended {
		command.Le = 65536
	}

	return command
}

func (s *recordSession) unprotect(
	command iso7816.Command,
	response iso7816.Response,
	rnd [aes.BlockSize]byte,
) (iso7816.Response, error) {
	keys, changed, err := s.keyChange(command)
	if err != nil {
		return iso7816.Response{}, err
	}

	// Key replacement authenticates its response with the new keys (Sec. 7.5).
	// Commit them only after accepting the complete response.
	var replacement recordSession

	current := s
	if changed && response.Status == iso7816.StatusSuccess && len(keys.ENC) != 0 {
		replacement, err = newRecordSession(keys, s.encoding, s.macLength)
		if err != nil {
			return iso7816.Response{}, err
		}
		defer replacement.clear()

		current = &replacement
	}

	var plaintext []byte

	if command.Le == 0 {
		// Sec. 7.5 explicitly excludes DO 99 and response MAC for commands
		// without a logical Le, even though the protected envelope has Le 00.
		if len(response.Data) != 0 {
			return iso7816.Response{}, fmt.Errorf("%w: data in status-only SM response", ErrInvalidResponse)
		}
	} else {
		encrypted, status, authenticated, receivedMAC, err := parseProtectedResponse(command.INS, response.Data, s.macLength)
		if err != nil {
			return iso7816.Response{}, err
		}

		if status != response.Status {
			return iso7816.Response{}, fmt.Errorf("%w: protected and outer status words differ", ErrInvalidResponse)
		}

		expected := cmac(current.mac, rnd, pad(authenticated))
		if subtle.ConstantTimeCompare(expected[:s.macLength], receivedMAC) != 1 {
			return iso7816.Response{}, fmt.Errorf("%w: response MAC: %w", ErrInvalidResponse, ErrAuthentication)
		}

		if encrypted != nil {
			plaintext, err = decrypt(current.enc, rnd, encrypted)
			if err != nil {
				return iso7816.Response{}, err
			}
		}
	}

	if response.Status == iso7816.StatusSuccess && changed {
		s.clear()

		if len(keys.ENC) != 0 {
			*s = replacement
			replacement = recordSession{}
		}
	}

	return iso7816.Response{Data: plaintext, Status: response.Status}, nil
}

// parseProtectedResponse authenticates the original BER representation, not a
// re-encoding. Only [encrypted data] DO 99 DO 8E, in that order, is defined.
func parseProtectedResponse(instruction byte, data []byte, macLength int) (
	encrypted []byte, status iso7816.StatusWord, authenticated, mac []byte, err error,
) {
	original := data

	tag, value, rest, err := bertlv.Parse(data)
	if err != nil {
		return nil, 0, nil, nil, fmt.Errorf("%w: protected response: %w", ErrInvalidResponse, err)
	}

	encryptedTag := uint32(0x87)
	if instruction&1 != 0 {
		encryptedTag = 0x85
	}

	if tag == encryptedTag {
		if encryptedTag == 0x87 {
			if len(value) == 0 || value[0] != 1 {
				return nil, 0, nil, nil, fmt.Errorf("%w: SM padding indicator", ErrInvalidResponse)
			}

			value = value[1:]
		}

		if len(value) == 0 || len(value)%aes.BlockSize != 0 {
			return nil, 0, nil, nil, fmt.Errorf("%w: SM ciphertext length", ErrInvalidResponse)
		}

		encrypted = value

		tag, value, rest, err = bertlv.Parse(rest)
		if err != nil {
			return nil, 0, nil, nil, fmt.Errorf("%w: SM status: %w", ErrInvalidResponse, err)
		}
	}

	if tag != 0x99 || len(value) != 2 {
		return nil, 0, nil, nil, fmt.Errorf("%w: SM status object", ErrInvalidResponse)
	}

	status = iso7816.NewStatusWord(value[0], value[1])
	authenticated = original[:len(original)-len(rest)]

	tag, value, rest, err = bertlv.Parse(rest)
	if err != nil {
		return nil, 0, nil, nil, fmt.Errorf("%w: SM response MAC: %w", ErrInvalidResponse, err)
	}

	if tag != 0x8e || len(value) != macLength || len(rest) != 0 {
		return nil, 0, nil, nil, fmt.Errorf("%w: SM response MAC object", ErrInvalidResponse)
	}

	return encrypted, status, authenticated, value, nil
}

// commandLe preserves the logical command's Le width, independently of the
// protected envelope's encoding. The extended-length marker is not part of DO 97.
func commandLe(command iso7816.Command) []byte {
	if command.Encoding == iso7816.EncodingExtended ||
		(command.Encoding == iso7816.EncodingAuto && (len(command.Data) > 255 || command.Le > 256)) {
		return []byte{byte(command.Le >> 8), byte(command.Le)}
	}

	return []byte{byte(command.Le)}
}

// objectSize counts a one-byte tag, its BER length, and its value.
func objectSize(size int) int {
	switch {
	case size < 128:
		return size + 2
	case size < 256:
		return size + 3
	case size < 65536:
		return size + 4
	default:
		return size + 5
	}
}

func (s *recordSession) clear() {
	clear(s.keys.ENC)
	clear(s.keys.MAC)
	*s = recordSession{}
}
