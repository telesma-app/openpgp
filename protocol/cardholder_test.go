package protocol_test

import (
	"testing"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/openpgp/protocol"
)

func TestCardholderRelatedData(t *testing.T) {
	data := bertlv.Append(nil, 0x5b, []byte("Example<<Alice"))
	data = bertlv.Append(data, 0x5f2d, []byte("enru"))
	data = bertlv.Append(data, 0x5f35, []byte{'2'})

	got, err := protocol.ParseCardholderRelatedData(bertlv.Append(nil, 0x65, data))
	if err != nil {
		t.Fatal(err)
	}

	if string(got.Name) != "Example<<Alice" || got.LanguagePreferences != "enru" || got.Sex != protocol.SexFemale {
		t.Errorf("cardholder = %+v", got)
	}
}

func TestUnconfiguredCardholder(t *testing.T) {
	got, err := protocol.ParseCardholderRelatedData([]byte{0x65, 9, 0x5b, 0, 0x5f, 0x2d, 0, 0x5f, 0x35, 1, '9'})
	if err != nil {
		t.Fatal(err)
	}

	if len(got.Name) != 0 || got.LanguagePreferences != "" || got.Sex != protocol.SexNotApplicable {
		t.Errorf("cardholder = %+v", got)
	}
}
