package protocol

import (
	"fmt"

	"github.com/telesma-app/iso7816"
)

// Secs. 6, 6.1 and 6.2: Historical Bytes, Card Capabilities, then Card Service Data.

// LifeCycleStatus is the historical bytes' status indicator (Sec. 6).
// Unknown values are retained.
type LifeCycleStatus byte

const (
	LifeCycleStatusNoInformation  LifeCycleStatus = 0
	LifeCycleStatusInitialization LifeCycleStatus = 3
	LifeCycleStatusOperational    LifeCycleStatus = 5
)

// HistoricalBytes describes DO 5F52 (Sec. 6). Raw borrows the complete input,
// including unknown COMPACT-TLV objects. Nil pointers identify absent fields.
// Category 10 exposes only its DIR data reference; proprietary and reserved
// categories remain opaque. An empty object contains no category or status.
type HistoricalBytes struct {
	Raw               []byte
	CategoryIndicator byte
	CardCapabilities  *CardCapabilities
	CardServiceData   *CardServiceData
	LifeCycleStatus   *LifeCycleStatus
	StatusWord        *iso7816.StatusWord
	DIRDataReference  *byte
}

func ParseHistoricalBytes(data []byte) (HistoricalBytes, error) {
	if len(data) > 15 {
		return HistoricalBytes{}, fmt.Errorf("%w: historical bytes length", ErrInvalidResponse)
	}

	historical := HistoricalBytes{Raw: data}
	if len(data) == 0 {
		return historical, nil
	}

	historical.CategoryIndicator = data[0]
	data = data[1:]

	switch historical.CategoryIndicator {
	case 0x00:
		if len(data) < 3 {
			return HistoricalBytes{}, fmt.Errorf("%w: missing historical status indicator", ErrInvalidResponse)
		}

		status := data[len(data)-3:]
		historical.LifeCycleStatus = new(LifeCycleStatus(status[0]))
		historical.StatusWord = new(iso7816.NewStatusWord(status[1], status[2]))
		data = data[:len(data)-3]
	case 0x80:
	case 0x10:
		if len(data) == 0 {
			return HistoricalBytes{}, fmt.Errorf("%w: missing DIR data reference", ErrInvalidResponse)
		}

		historical.DIRDataReference = new(data[0])

		return historical, nil
	default:
		return historical, nil
	}

	for len(data) != 0 {
		tag, length := data[0]>>4, int(data[0]&0xf)
		data = data[1:]

		if length > len(data) {
			return HistoricalBytes{}, fmt.Errorf("%w: truncated historical COMPACT-TLV", ErrInvalidResponse)
		}

		value := data[:length]
		data = data[length:]

		switch tag {
		case 3:
			if historical.CardServiceData != nil {
				return HistoricalBytes{}, fmt.Errorf("%w: duplicate card service data", ErrInvalidResponse)
			}

			service, err := ParseCardServiceData(value)
			if err != nil {
				return HistoricalBytes{}, err
			}

			historical.CardServiceData = &service
		case 7:
			if historical.CardCapabilities != nil {
				return HistoricalBytes{}, fmt.Errorf("%w: duplicate card capabilities", ErrInvalidResponse)
			}

			capabilities, err := ParseCardCapabilities(value)
			if err != nil {
				return HistoricalBytes{}, err
			}

			historical.CardCapabilities = &capabilities
		case 8:
			if historical.CategoryIndicator != 0x80 {
				continue
			}

			// ISO/IEC 7816-4 places the category-80 status indicator last.
			if len(data) != 0 {
				return HistoricalBytes{}, fmt.Errorf("%w: historical status indicator is not last", ErrInvalidResponse)
			}

			switch len(value) {
			case 1:
				historical.LifeCycleStatus = new(LifeCycleStatus(value[0]))
			case 2:
				historical.StatusWord = new(iso7816.NewStatusWord(value[0], value[1]))
			case 3:
				historical.LifeCycleStatus = new(LifeCycleStatus(value[0]))
				historical.StatusWord = new(iso7816.NewStatusWord(value[1], value[2]))
			default:
				return HistoricalBytes{}, fmt.Errorf("%w: historical status indicator length", ErrInvalidResponse)
			}
		}
	}

	return historical, nil
}

// LogicalChannelAssignment is bits 5-4 of the third software function table,
// shifted to the low two bits (Sec. 6.1; ISO/IEC 7816-4, Table 119).
type LogicalChannelAssignment byte

const (
	LogicalChannelAssignmentBasicOnly                LogicalChannelAssignment = 0
	LogicalChannelAssignmentByInterfaceDevice        LogicalChannelAssignment = 1
	LogicalChannelAssignmentByCard                   LogicalChannelAssignment = 2
	LogicalChannelAssignmentByCardAndInterfaceDevice LogicalChannelAssignment = 3
)

// CardCapabilities contains the three software function tables (Sec. 6.1).
// Only the third table is interpreted by the OpenPGP application. A
// MaxLogicalChannels value of 8 means eight or more, rather than exactly eight.
type CardCapabilities struct {
	Raw                                  [3]byte
	CommandChaining                      bool
	ExtendedLength                       bool
	ExtendedLengthInformationInEFATRInfo bool
	LogicalChannelAssignment             LogicalChannelAssignment
	MaxLogicalChannels                   byte
}

func ParseCardCapabilities(data []byte) (CardCapabilities, error) {
	if len(data) != 3 {
		return CardCapabilities{}, fmt.Errorf("%w: card capabilities length", ErrInvalidResponse)
	}

	return CardCapabilities{
		Raw: [3]byte(data), CommandChaining: data[2]&0x80 != 0,
		ExtendedLength: data[2]&0x40 != 0, ExtendedLengthInformationInEFATRInfo: data[2]&0x20 != 0,
		LogicalChannelAssignment: LogicalChannelAssignment(data[2] >> 3 & 3),
		MaxLogicalChannels:       (data[2] & 7) + 1,
	}, nil
}

// CardServiceAccessServices is bits 4-2 of the card service data byte, shifted
// to the low three bits (Sec. 6.2; ISO/IEC 7816-4, Table 115).
// Other values are reserved and retained unchanged.
type CardServiceAccessServices byte

const (
	CardServiceAccessReadRecords CardServiceAccessServices = 0
	CardServiceAccessGetData     CardServiceAccessServices = 2
	CardServiceAccessReadBinary  CardServiceAccessServices = 4
)

// CardServiceData describes application selection and EF.DIR/EF.ATR/INFO
// availability and access services (Sec. 6.2).
type CardServiceData struct {
	Raw                    byte
	FullDFNameSelection    bool
	PartialDFNameSelection bool
	EFDirDataObjects       bool
	EFATRInfoDataObjects   bool
	AccessServices         CardServiceAccessServices
	MasterFile             bool
}

func ParseCardServiceData(data []byte) (CardServiceData, error) {
	if len(data) != 1 {
		return CardServiceData{}, fmt.Errorf("%w: card service data length", ErrInvalidResponse)
	}

	return CardServiceData{
		Raw: data[0], FullDFNameSelection: data[0]&0x80 != 0, PartialDFNameSelection: data[0]&0x40 != 0,
		EFDirDataObjects: data[0]&0x20 != 0, EFATRInfoDataObjects: data[0]&0x10 != 0,
		AccessServices: CardServiceAccessServices(data[0] >> 1 & 7), MasterFile: data[0]&1 == 0,
	}, nil
}
