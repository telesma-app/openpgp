package protocol_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/openpgp/protocol"
)

func TestApplicationRelatedDataUserInteractionFlags(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		data := applicationWithUserInteractionFlags([]byte{0xd6, 2, 1, 0x20, 0xd7, 2, 0, 0x20, 0xd8, 2, 2, 0x20})
		if wrapped {
			data = bertlv.Append(nil, 0x6e, data)
		}

		got, err := protocol.ParseApplicationRelatedData(data)
		if err != nil {
			t.Fatal(err)
		}

		for _, field := range []struct {
			name string
			got  *protocol.UserInteractionFlag
			want protocol.UIFState
		}{
			{"signature", got.SignatureUIF, protocol.UIFEnabled},
			{"decryption", got.DecryptionUIF, protocol.UIFDisabled},
			{"authentication", got.AuthenticationUIF, protocol.UIFPermanentlyEnabled},
		} {
			if field.got == nil || field.got.State != field.want || field.got.Features != protocol.GeneralFeatureButton {
				t.Errorf("%s UIF = %+v, want state %d and button", field.name, field.got, field.want)
			}
		}

		if !bytes.Equal(got.Raw, data) {
			t.Errorf("raw application = %x, want %x", got.Raw, data)
		}
	}
}

func TestApplicationRelatedDataUserInteractionFlagPresence(t *testing.T) {
	got, err := protocol.ParseApplicationRelatedData(applicationWithUserInteractionFlags([]byte{0xd7, 2, 0, 0}))
	if err != nil {
		t.Fatal(err)
	}

	if got.SignatureUIF != nil || got.AuthenticationUIF != nil {
		t.Errorf("omitted flags were populated: %+v / %+v", got.SignatureUIF, got.AuthenticationUIF)
	}

	if got.DecryptionUIF == nil || *got.DecryptionUIF != (protocol.UserInteractionFlag{}) {
		t.Errorf("present disabled UIF = %+v, want explicit zero value", got.DecryptionUIF)
	}
}

func TestApplicationRelatedDataUserInteractionFlagUnknownState(t *testing.T) {
	got, err := protocol.ParseApplicationRelatedData(applicationWithUserInteractionFlags([]byte{0xd8, 2, 0x7f, 0xa5}))
	if err != nil {
		t.Fatal(err)
	}

	if got.AuthenticationUIF == nil || got.AuthenticationUIF.State != 0x7f || got.AuthenticationUIF.Features != 0xa5 {
		t.Errorf("unknown UIF = %+v", got.AuthenticationUIF)
	}
}

func TestApplicationRelatedDataMalformedUserInteractionFlags(t *testing.T) {
	for _, data := range [][]byte{
		{0xd6, 0},
		{0xd7, 1, 0},
		{0xd8, 3, 1, 0x20, 0},
		{0xd6, 2, 0, 0x20, 0xd6, 2, 1, 0x20},
	} {
		_, err := protocol.ParseApplicationRelatedData(applicationWithUserInteractionFlags(data))
		if !errors.Is(err, protocol.ErrInvalidResponse) {
			t.Errorf("UIF data %x: error = %v, want ErrInvalidResponse", data, err)
		}
	}
}

func applicationWithUserInteractionFlags(flags []byte) []byte {
	data := bertlv.Append(nil, 0x4f, []byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 6, 0, 0, 0, 0, 0, 0})

	return bertlv.Append(data, 0x73, flags)
}
