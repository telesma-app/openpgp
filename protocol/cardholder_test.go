package protocol_test

import (
	"bytes"
	"errors"
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

func TestCardholderRelatedDataFields(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
		want protocol.CardholderRelatedData
	}{
		{name: "omitted fields"},
		{name: "empty template", data: []byte{0x65, 0}},
		{
			name: "maximum name length in bytes",
			data: bertlv.Append(nil, 0x5b, bytes.Repeat([]byte{0xe9}, 39)),
			want: protocol.CardholderRelatedData{Name: bytes.Repeat([]byte{0xe9}, 39)},
		},
		{
			name: "ISO 8859-1 name and separators",
			data: []byte{0x5b, 5, 0xc9, 'x', '<', '<', 'A'},
			want: protocol.CardholderRelatedData{Name: []byte{0xc9, 'x', '<', '<', 'A'}},
		},
		{
			name: "one language", data: []byte{0x5f, 0x2d, 2, 'a', 'z'},
			want: protocol.CardholderRelatedData{LanguagePreferences: "az"},
		},
		{
			name: "four languages", data: []byte{0x5f, 0x2d, 8, 'e', 'n', 'r', 'u', 's', 'r', 'i', 't'},
			want: protocol.CardholderRelatedData{LanguagePreferences: "enrusrit"},
		},
		{
			name: "sex not known", data: []byte{0x5f, 0x35, 1, '0'},
			want: protocol.CardholderRelatedData{Sex: protocol.SexNotKnown},
		},
		{
			name: "sex male", data: []byte{0x5f, 0x35, 1, '1'},
			want: protocol.CardholderRelatedData{Sex: protocol.SexMale},
		},
		{
			name: "sex female", data: []byte{0x5f, 0x35, 1, '2'},
			want: protocol.CardholderRelatedData{Sex: protocol.SexFemale},
		},
		{
			name: "sex not applicable", data: []byte{0x5f, 0x35, 1, '9'},
			want: protocol.CardholderRelatedData{Sex: protocol.SexNotApplicable},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := protocol.ParseCardholderRelatedData(test.data)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got.Name, test.want.Name) || got.LanguagePreferences != test.want.LanguagePreferences || got.Sex != test.want.Sex {
				t.Errorf("cardholder = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestCardholderRelatedDataRejectsMalformedResponse(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "name exceeds byte limit", data: bertlv.Append(nil, 0x5b, bytes.Repeat([]byte{0xe9}, 40))},
		{name: "one language byte", data: []byte{0x5f, 0x2d, 1, 'e'}},
		{name: "odd language length", data: []byte{0x5f, 0x2d, 3, 'e', 'n', 'r'}},
		{name: "too many languages", data: bertlv.Append(nil, 0x5f2d, []byte("enrusritde"))},
		{name: "language below lowercase range", data: []byte{0x5f, 0x2d, 2, '`', 'z'}},
		{name: "language above lowercase range", data: []byte{0x5f, 0x2d, 2, 'a', '{'}},
		{name: "uppercase language", data: []byte{0x5f, 0x2d, 2, 'E', 'N'}},
		{name: "empty sex", data: []byte{0x5f, 0x35, 0}},
		{name: "long sex", data: []byte{0x5f, 0x35, 2, '1', '2'}},
		{name: "unknown sex", data: []byte{0x5f, 0x35, 1, '3'}},
		{name: "binary sex", data: []byte{0x5f, 0x35, 1, 1}},
		{name: "truncated template", data: []byte{0x65, 3, 0x5b, 2}},
		{name: "truncated field", data: []byte{0x5b, 2, 'A'}},
		{name: "duplicate field", data: []byte{0x5b, 1, 'A', 0x5b, 1, 'B'}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := protocol.ParseCardholderRelatedData(test.data)
			if !errors.Is(err, protocol.ErrInvalidResponse) {
				t.Errorf("error = %v, want ErrInvalidResponse", err)
			}

			if got.Name != nil || got.LanguagePreferences != "" || got.Sex != 0 {
				t.Errorf("cardholder = %+v, want zero result", got)
			}
		})
	}
}
