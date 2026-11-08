package protocol

import "fmt"

// GeneralFeatureManagementFlags is the first byte of DO 81 inside General
// Feature Management (Sec. 4.1.3.2).
type GeneralFeatureManagementFlags byte

const (
	GeneralFeatureDisplay              GeneralFeatureManagementFlags = 0x80
	GeneralFeatureBiometricInputSensor GeneralFeatureManagementFlags = 0x40
	GeneralFeatureButton               GeneralFeatureManagementFlags = 0x20
	GeneralFeatureKeypad               GeneralFeatureManagementFlags = 0x10
	GeneralFeatureLED                  GeneralFeatureManagementFlags = 0x08
	GeneralFeatureLoudspeaker          GeneralFeatureManagementFlags = 0x04
	GeneralFeatureMicrophone           GeneralFeatureManagementFlags = 0x02
	GeneralFeatureTouchscreen          GeneralFeatureManagementFlags = 0x01
)

// GeneralFeatureManagement describes additional user-interaction hardware.
// Only the first byte of DO 81 is interpreted. Raw borrows the response and
// retains extension bytes and unknown child DOs.
type GeneralFeatureManagement struct {
	Raw      []byte
	Features GeneralFeatureManagementFlags
}

// ParseGeneralFeatureManagement accepts the complete 7F74 template or its
// child DOs (Sec. 4.1.3.2).
func ParseGeneralFeatureManagement(data []byte) (GeneralFeatureManagement, error) {
	raw := data

	data, err := constructedContents(data, 0x7f74)
	if err != nil {
		return GeneralFeatureManagement{}, err
	}

	fields, err := objectFields(data)
	if err != nil {
		return GeneralFeatureManagement{}, err
	}

	value := fields[0x81]
	if len(value) == 0 {
		return GeneralFeatureManagement{}, fmt.Errorf("%w: general feature management flags", ErrInvalidResponse)
	}

	return GeneralFeatureManagement{Raw: raw, Features: GeneralFeatureManagementFlags(value[0])}, nil
}
