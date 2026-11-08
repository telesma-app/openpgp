package protocol

import "fmt"

// Secs. 4.4.1 and 4.4.3.3-4.4.3.5: cardholder name, language preferences and sex.

// CardholderRelatedData is the user-editable GET DATA 65 metadata.
// Name retains ISO 8859-1 bytes and '<' separators. LanguagePreferences contains
// concatenated ISO 639-1 codes; Sex is ASCII ('0', '1', '2', '9'), or zero if absent.
type CardholderRelatedData struct {
	Name                []byte
	LanguagePreferences string
	Sex                 Sex
}

func ParseCardholderRelatedData(data []byte) (CardholderRelatedData, error) {
	data, err := constructedContents(data, 0x65)
	if err != nil {
		return CardholderRelatedData{}, err
	}

	fields, err := objectFields(data)
	if err != nil {
		return CardholderRelatedData{}, err
	}

	cardholder := CardholderRelatedData{Name: fields[0x5b]}
	if len(cardholder.Name) > 39 {
		return CardholderRelatedData{}, fmt.Errorf("%w: cardholder name length", ErrInvalidResponse)
	}

	if value, present := fields[0x5f2d]; present {
		// Unconfigured YubiKey and TOKEN2 applets return an empty language DO.
		if len(value) > 8 || len(value)%2 != 0 {
			return CardholderRelatedData{}, fmt.Errorf("%w: language preferences length", ErrInvalidResponse)
		}

		for _, b := range value {
			if b < 'a' || b > 'z' {
				return CardholderRelatedData{}, fmt.Errorf("%w: language preferences encoding", ErrInvalidResponse)
			}
		}

		cardholder.LanguagePreferences = string(value)
	}

	if value, present := fields[0x5f35]; present {
		if len(value) != 1 {
			return CardholderRelatedData{}, fmt.Errorf("%w: sex length", ErrInvalidResponse)
		}

		switch sex := Sex(value[0]); sex {
		case SexNotKnown, SexMale, SexFemale, SexNotApplicable:
			cardholder.Sex = sex
		default:
			return CardholderRelatedData{}, fmt.Errorf("%w: sex encoding", ErrInvalidResponse)
		}
	}

	return cardholder, nil
}

// Sex uses the ISO 5218 values in ASCII coding (Sec. 4.4.3.5).
type Sex byte

const (
	SexNotKnown      Sex = '0'
	SexMale          Sex = '1'
	SexFemale        Sex = '2'
	SexNotApplicable Sex = '9'
)
