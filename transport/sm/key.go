// Static secure messaging keys and their replacement with PUT DATA (Sec. 7.5).
package sm

import (
	"fmt"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

// Keys contains the static keys provisioned in SM-Key-ENC and SM-Key-MAC.
// Both keys must contain 16 bytes for AES-128 or 32 bytes for AES-256.
type Keys struct {
	ENC []byte
	MAC []byte
}

// keyChange describes the response keys after a successful PUT DATA. F4 contains
// the two child DOs D1 and D2, without an outer F4 tag (Sec. 4.4.2).
func (s *recordSession) keyChange(command iso7816.Command) (Keys, bool, error) {
	if command.INS != byte(protocol.PutData) {
		return s.keys, false, nil
	}

	keys := s.keys

	switch protocol.Object(uint16(command.P1)<<8 | uint16(command.P2)) {
	case protocol.SMKeyENCObject:
		keys.ENC = command.Data
	case protocol.SMKeyMACObject:
		keys.MAC = command.Data
	case protocol.SMKeyContainerObject:
		if len(command.Data) == 0 {
			keys = Keys{}
			break
		}

		tag, enc, rest, err := bertlv.Parse(command.Data)
		if err != nil || tag != uint32(protocol.SMKeyENCObject) {
			return Keys{}, false, fmt.Errorf("%w: SM key container ENC object", iso7816.ErrInvalidCommand)
		}

		tag, mac, rest, err := bertlv.Parse(rest)
		if err != nil || tag != uint32(protocol.SMKeyMACObject) || len(rest) != 0 {
			return Keys{}, false, fmt.Errorf("%w: SM key container MAC object", iso7816.ErrInvalidCommand)
		}

		keys = Keys{ENC: enc, MAC: mac}
	default:
		return s.keys, false, nil
	}

	if len(keys.ENC) == 0 && len(keys.MAC) == 0 {
		if command.Le != 0 {
			return Keys{}, false, fmt.Errorf("%w: SM key deletion requires a status-only response", iso7816.ErrInvalidCommand)
		}
	} else if len(keys.ENC) != len(s.keys.ENC) || len(keys.MAC) != len(s.keys.MAC) {
		return Keys{}, false, fmt.Errorf("%w: replacement SM keys must match the advertised AES size", iso7816.ErrInvalidCommand)
	}

	return keys, true, nil
}
