package protocol

import "fmt"

// UIFState is the first byte of a User Interaction Flag DO (Sec. 4.4.3.6).
type UIFState byte

const (
	UIFDisabled           UIFState = 0
	UIFEnabled            UIFState = 1
	UIFPermanentlyEnabled UIFState = 2
)

// UserInteractionFlag contains the state and user-interaction hardware flags
// from DO D6, D7 or D8 (Secs. 4.4.1 and 4.4.3.6). Features uses the first-byte
// coding of General Feature Management. Unknown and reserved states are retained.
type UserInteractionFlag struct {
	State    UIFState
	Features GeneralFeatureManagementFlags
}

// ParseUserInteractionFlag parses the two value bytes of a UIF data object.
// As a simple DO, UIF does not include a BER-TLV tag or length in GET DATA.
func ParseUserInteractionFlag(data []byte) (UserInteractionFlag, error) {
	if len(data) != 2 {
		return UserInteractionFlag{}, fmt.Errorf("%w: user interaction flag length", ErrInvalidResponse)
	}

	return UserInteractionFlag{State: UIFState(data[0]), Features: GeneralFeatureManagementFlags(data[1])}, nil
}

// EncodeUserInteractionFlag returns the two value bytes for PUT DATA.
// The state and hardware flags are sent unchanged. The caller owns the result.
func EncodeUserInteractionFlag(flag UserInteractionFlag) []byte {
	return []byte{byte(flag.State), byte(flag.Features)}
}
