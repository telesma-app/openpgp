package protocol_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/telesma-app/openpgp/protocol"
)

// OpenPGP Card 3.4.1, Secs. 4.4.1, 4.4.2 and 4.4.3.6 define a two-byte
// simple DO value: state followed by general feature management flags.
// The USB and contactless application fixtures both report 00 20 for D6-D8.
// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf
func TestUserInteractionFlag(t *testing.T) {
	for _, tt := range []struct {
		name string
		data []byte
		want protocol.UserInteractionFlag
	}{
		{
			name: "disabled", data: []byte{0, 0x20},
			want: protocol.UserInteractionFlag{State: protocol.UIFDisabled, Features: protocol.GeneralFeatureButton},
		},
		{
			name: "enabled", data: []byte{1, 0x20},
			want: protocol.UserInteractionFlag{State: protocol.UIFEnabled, Features: protocol.GeneralFeatureButton},
		},
		{
			name: "permanently enabled", data: []byte{2, 0x20},
			want: protocol.UserInteractionFlag{State: protocol.UIFPermanentlyEnabled, Features: protocol.GeneralFeatureButton},
		},
		{
			name: "reserved state 03", data: []byte{3, 0x20},
			want: protocol.UserInteractionFlag{State: 3, Features: protocol.GeneralFeatureButton},
		},
		{
			name: "reserved state 04", data: []byte{4, 0},
			want: protocol.UserInteractionFlag{State: 4},
		},
		{
			name: "unknown state and all feature bits", data: []byte{0x7f, 0xff},
			want: protocol.UserInteractionFlag{State: 0x7f, Features: 0xff},
		},
		{
			name: "zero features", data: []byte{1, 0},
			want: protocol.UserInteractionFlag{State: protocol.UIFEnabled},
		},
		{
			name: "combined hardware features", data: []byte{1, 0xb1},
			want: protocol.UserInteractionFlag{
				State: protocol.UIFEnabled,
				Features: protocol.GeneralFeatureDisplay | protocol.GeneralFeatureButton |
					protocol.GeneralFeatureKeypad | protocol.GeneralFeatureTouchscreen,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := protocol.ParseUserInteractionFlag(tt.data)
			if err != nil {
				t.Fatal(err)
			}

			if got != tt.want {
				t.Errorf("flag = %+v, want %+v", got, tt.want)
			}

			encoded := protocol.EncodeUserInteractionFlag(tt.want)
			if !bytes.Equal(encoded, tt.data) {
				t.Errorf("encoded flag = %x, want %x", encoded, tt.data)
			}
		})
	}
}

func TestUserInteractionFlagOwnsEncodedValue(t *testing.T) {
	data := []byte{1, 0x21}

	flag, err := protocol.ParseUserInteractionFlag(data)
	if err != nil {
		t.Fatal(err)
	}

	encoded := protocol.EncodeUserInteractionFlag(flag)
	data[0], data[1] = 2, 0

	if !bytes.Equal(encoded, []byte{1, 0x21}) {
		t.Errorf("encoded flag changed with the response: %x", encoded)
	}

	clear(encoded)

	want := protocol.UserInteractionFlag{
		State: protocol.UIFEnabled, Features: protocol.GeneralFeatureButton | protocol.GeneralFeatureTouchscreen,
	}
	if flag != want || !bytes.Equal(data, []byte{2, 0}) {
		t.Errorf("clearing the encoded value changed the parsed flag or response: %+v / %x", flag, data)
	}
}

func TestUserInteractionFlagMalformedResponse(t *testing.T) {
	for _, tt := range []struct {
		name string
		data []byte
	}{
		{name: "absent value"},
		{name: "empty value", data: []byte{}},
		{name: "missing feature byte", data: []byte{1}},
		{name: "trailing byte", data: []byte{1, 0x20, 0}},
		{name: "full D6 TLV", data: []byte{0xd6, 2, 1, 0x20}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := protocol.ParseUserInteractionFlag(tt.data)
			if !errors.Is(err, protocol.ErrInvalidResponse) {
				t.Errorf("flag %x: error = %v, want ErrInvalidResponse", tt.data, err)
			}
		})
	}
}
