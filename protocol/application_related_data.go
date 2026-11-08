package protocol

import (
	"encoding/binary"
	"fmt"
)

// ApplicationRelatedData is the GET DATA 6E metadata (Sec. 4.4.3.1).
// Only AID is required; nil pointers and Algorithm zero mark omitted fields,
// which remain individually readable with GET DATA. Fingerprints and key dates
// use SIG, DEC, AUT order, then vendor keys; zero entries mean unspecified.
// Raw and other byte slices borrow the response.
type ApplicationRelatedData struct {
	Raw                               []byte
	AID                               ApplicationIdentifier
	HistoricalBytes                   *HistoricalBytes
	ExtendedLengthInformation         *ExtendedLengthInformation
	GeneralFeatureManagement          *GeneralFeatureManagement
	ExtendedCapabilities              *ExtendedCapabilities
	SignatureAlgorithmAttributes      AlgorithmAttributes
	DecryptionAlgorithmAttributes     AlgorithmAttributes
	AuthenticationAlgorithmAttributes AlgorithmAttributes
	PWStatusBytes                     *PWStatusBytes
	SignatureUIF                      *UserInteractionFlag
	DecryptionUIF                     *UserInteractionFlag
	AuthenticationUIF                 *UserInteractionFlag
	Fingerprints                      [][20]byte
	CAFingerprints                    [][20]byte
	KeyGenerationTimes                []uint32
	KeyInformation                    []KeyInformation
}

func ParseApplicationRelatedData(data []byte) (ApplicationRelatedData, error) {
	raw := data

	data, err := constructedContents(data, 0x6e)
	if err != nil {
		return ApplicationRelatedData{}, err
	}

	fields, err := objectFields(data)
	if err != nil {
		return ApplicationRelatedData{}, err
	}

	application := ApplicationRelatedData{Raw: raw}

	application.AID, err = ParseApplicationIdentifier(fields[0x4f])
	if err != nil {
		return ApplicationRelatedData{}, err
	}

	if value, present := fields[0x5f52]; present {
		historical, err := ParseHistoricalBytes(value)
		if err != nil {
			return ApplicationRelatedData{}, err
		}

		application.HistoricalBytes = &historical
	}

	if value, present := fields[0x7f66]; present {
		information, err := ParseExtendedLengthInformation(value)
		if err != nil {
			return ApplicationRelatedData{}, err
		}

		application.ExtendedLengthInformation = &information
	}

	if value, present := fields[0x7f74]; present {
		features, err := ParseGeneralFeatureManagement(value)
		if err != nil {
			return ApplicationRelatedData{}, err
		}

		application.GeneralFeatureManagement = &features
	}

	if discretionary, present := fields[0x73]; present {
		if err := parseDiscretionaryData(&application, discretionary); err != nil {
			return ApplicationRelatedData{}, err
		}
	}

	return application, nil
}

func parseDiscretionaryData(application *ApplicationRelatedData, data []byte) error {
	fields, err := objectFields(data)
	if err != nil {
		return err
	}

	// Some cards include 7F66 inside 73 rather than at the root of 6E.
	if value, present := fields[0x7f66]; present && application.ExtendedLengthInformation == nil {
		information, err := ParseExtendedLengthInformation(value)
		if err != nil {
			return err
		}

		application.ExtendedLengthInformation = &information
	}

	if value, present := fields[0xc0]; present {
		capabilities, err := ParseExtendedCapabilities(value)
		if err != nil {
			return err
		}

		application.ExtendedCapabilities = &capabilities
	}

	for tag, destination := range map[uint32]*AlgorithmAttributes{
		0xc1: &application.SignatureAlgorithmAttributes,
		0xc2: &application.DecryptionAlgorithmAttributes,
		0xc3: &application.AuthenticationAlgorithmAttributes,
	} {
		if value, present := fields[tag]; present {
			*destination, err = ParseAlgorithmAttributes(value)
			if err != nil {
				return err
			}
		}
	}

	if value, present := fields[0xc4]; present {
		status, err := ParsePWStatusBytes(value)
		if err != nil {
			return err
		}

		application.PWStatusBytes = &status
	}

	for tag, destination := range map[uint32]**UserInteractionFlag{
		0xd6: &application.SignatureUIF,
		0xd7: &application.DecryptionUIF,
		0xd8: &application.AuthenticationUIF,
	} {
		if value, present := fields[tag]; present {
			flag, err := ParseUserInteractionFlag(value)
			if err != nil {
				return err
			}

			*destination = &flag
		}
	}

	for tag, destination := range map[uint32]*[][20]byte{
		0xc5: &application.Fingerprints,
		0xc6: &application.CAFingerprints,
	} {
		if value, present := fields[tag]; present {
			if len(value) < 60 || len(value)%20 != 0 {
				return fmt.Errorf("%w: fingerprint list length", ErrInvalidResponse)
			}

			*destination = make([][20]byte, len(value)/20)
			for i := range *destination {
				copy((*destination)[i][:], value[i*20:(i+1)*20])
			}
		}
	}

	if value, present := fields[0xcd]; present {
		if len(value) < 12 || len(value)%4 != 0 {
			return fmt.Errorf("%w: key generation time list length", ErrInvalidResponse)
		}

		application.KeyGenerationTimes = make([]uint32, len(value)/4)
		for i := range application.KeyGenerationTimes {
			application.KeyGenerationTimes[i] = binary.BigEndian.Uint32(value[i*4 : (i+1)*4])
		}
	}

	if value, present := fields[0xde]; present {
		application.KeyInformation, err = ParseKeyInformation(value)
		if err != nil {
			return err
		}
	}

	return nil
}
