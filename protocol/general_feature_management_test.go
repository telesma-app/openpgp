package protocol_test

import (
	"errors"
	"testing"

	"github.com/telesma-app/openpgp/protocol"
)

func TestGeneralFeatureManagement(t *testing.T) {
	for _, test := range []struct {
		name     string
		data     []byte
		features protocol.GeneralFeatureManagementFlags
	}{
		{name: "body", data: []byte{0x81, 1, 0x20}, features: protocol.GeneralFeatureButton},
		{name: "template", data: []byte{0x7f, 0x74, 3, 0x81, 1, 0x20}, features: protocol.GeneralFeatureButton},
		{
			name: "extensions and unknown DO", data: []byte{0x81, 3, 0xff, 0xa5, 1, 0x82, 2, 0x12, 0x34},
			features: 0xff,
		},
		{
			name: "unknown two-byte tag before flags", data: []byte{0x7f, 0x66, 0, 0x81, 1, 0},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := protocol.ParseGeneralFeatureManagement(test.data)
			if err != nil {
				t.Fatal(err)
			}

			if got.Features != test.features {
				t.Errorf("features = %02x, want %02x", got.Features, test.features)
			}

			if len(got.Raw) != len(test.data) || &got.Raw[0] != &test.data[0] {
				t.Error("Raw does not borrow the complete input")
			}
		})
	}
}

func TestGeneralFeatureManagementFlagBits(t *testing.T) {
	for _, test := range []struct {
		name string
		wire byte
		flag protocol.GeneralFeatureManagementFlags
	}{
		{name: "display", wire: 0x80, flag: protocol.GeneralFeatureDisplay},
		{name: "biometric input sensor", wire: 0x40, flag: protocol.GeneralFeatureBiometricInputSensor},
		{name: "button", wire: 0x20, flag: protocol.GeneralFeatureButton},
		{name: "keypad", wire: 0x10, flag: protocol.GeneralFeatureKeypad},
		{name: "LED", wire: 0x08, flag: protocol.GeneralFeatureLED},
		{name: "loudspeaker", wire: 0x04, flag: protocol.GeneralFeatureLoudspeaker},
		{name: "microphone", wire: 0x02, flag: protocol.GeneralFeatureMicrophone},
		{name: "touchscreen", wire: 0x01, flag: protocol.GeneralFeatureTouchscreen},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := protocol.ParseGeneralFeatureManagement([]byte{0x81, 1, test.wire})
			if err != nil {
				t.Fatal(err)
			}

			if got.Features != test.flag {
				t.Errorf("features = %02x, want %02x", got.Features, test.flag)
			}
		})
	}
}

func TestGeneralFeatureManagementMalformed(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "empty"},
		{name: "missing flags", data: []byte{0x82, 1, 0x20}},
		{name: "empty flags", data: []byte{0x81, 0}},
		{name: "duplicate flags", data: []byte{0x81, 1, 0x20, 0x81, 1, 0x10}},
		{name: "truncated flags", data: []byte{0x81, 2, 0x20}},
		{name: "truncated unknown DO", data: []byte{0x81, 1, 0x20, 0x82, 1}},
		{name: "truncated template", data: []byte{0x7f, 0x74, 4, 0x81, 1, 0x20}},
		{name: "trailing template data", data: []byte{0x7f, 0x74, 3, 0x81, 1, 0x20, 0x82, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := protocol.ParseGeneralFeatureManagement(test.data)

			if !errors.Is(err, protocol.ErrInvalidResponse) {
				t.Fatalf("error = %v, want ErrInvalidResponse", err)
			}
		})
	}
}
