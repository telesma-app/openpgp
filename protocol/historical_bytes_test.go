package protocol_test

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

func TestCapturedHistoricalBytes(t *testing.T) {
	for _, test := range []struct {
		name         string
		thirdTable   byte
		extendedInfo bool
	}{
		{name: "USB", thirdTable: 0xe0, extendedInfo: true},
		{name: "contactless", thirdTable: 0xc0},
	} {
		t.Run(test.name, func(t *testing.T) {
			// DO 5F52 values from the existing application captures.
			data := []byte{0, 0x73, 0, 0, test.thirdTable, 5, 0x90, 0}

			got, err := protocol.ParseHistoricalBytes(data)
			if err != nil {
				t.Fatal(err)
			}

			want := protocol.HistoricalBytes{
				Raw: data, CategoryIndicator: 0,
				CardCapabilities: &protocol.CardCapabilities{
					Raw: [3]byte{0, 0, test.thirdTable}, CommandChaining: true, ExtendedLength: true,
					ExtendedLengthInformationInEFATRInfo: test.extendedInfo,
					LogicalChannelAssignment:             protocol.LogicalChannelAssignmentBasicOnly, MaxLogicalChannels: 1,
				},
				LifeCycleStatus: new(protocol.LifeCycleStatusOperational), StatusWord: new(iso7816.StatusWord(0x9000)),
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("historical bytes = %+v, want %+v", got, want)
			}
		})
	}
}

func TestHistoricalCompactMetadata(t *testing.T) {
	data := []byte{0, 0xb1, 0x42, 0x31, 0xf5, 0x73, 0xaa, 0xbb, 0xff, 3, 0x69, 0x85}

	got, err := protocol.ParseHistoricalBytes(data)
	if err != nil {
		t.Fatal(err)
	}

	want := protocol.HistoricalBytes{
		Raw: data,
		CardServiceData: &protocol.CardServiceData{
			Raw: 0xf5, FullDFNameSelection: true, PartialDFNameSelection: true,
			EFDirDataObjects: true, EFATRInfoDataObjects: true, AccessServices: protocol.CardServiceAccessGetData,
		},
		CardCapabilities: &protocol.CardCapabilities{
			Raw: [3]byte{0xaa, 0xbb, 0xff}, CommandChaining: true, ExtendedLength: true,
			ExtendedLengthInformationInEFATRInfo: true,
			LogicalChannelAssignment:             protocol.LogicalChannelAssignmentByCardAndInterfaceDevice, MaxLogicalChannels: 8,
		},
		LifeCycleStatus: new(protocol.LifeCycleStatusInitialization), StatusWord: new(iso7816.StatusWord(0x6985)),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("metadata = %+v, want %+v", got, want)
	}

	if &got.Raw[0] != &data[0] {
		t.Error("Raw does not borrow the input")
	}
}

func TestHistoricalStatusIndicators(t *testing.T) {
	for _, test := range []struct {
		name   string
		data   []byte
		life   *protocol.LifeCycleStatus
		status *iso7816.StatusWord
	}{
		{name: "00 unknown lifecycle and unreported SW", data: []byte{0, 0x42, 0, 0}, life: new(protocol.LifeCycleStatus(0x42)), status: new(iso7816.StatusWord(0))},
		{name: "80 no status", data: []byte{0x80}},
		{name: "80 lifecycle only", data: []byte{0x80, 0x81, 5}, life: new(protocol.LifeCycleStatusOperational)},
		{name: "80 SW only", data: []byte{0x80, 0x82, 0x62, 0x85}, status: new(iso7816.StatusWord(0x6285))},
		{name: "80 lifecycle and SW", data: []byte{0x80, 0x83, 3, 0x90, 0}, life: new(protocol.LifeCycleStatusInitialization), status: new(iso7816.StatusWord(0x9000))},
		{name: "80 explicit zero status", data: []byte{0x80, 0x83, 0, 0, 0}, life: new(protocol.LifeCycleStatusNoInformation), status: new(iso7816.StatusWord(0))},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := protocol.ParseHistoricalBytes(test.data)
			if err != nil {
				t.Fatal(err)
			}

			if got.CategoryIndicator != test.data[0] || !reflect.DeepEqual(got.LifeCycleStatus, test.life) || !reflect.DeepEqual(got.StatusWord, test.status) {
				t.Errorf("status = %+v, want lifecycle %v, SW %v", got, test.life, test.status)
			}
		})
	}
}

func TestHistoricalOpaqueFormats(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
		dir  *byte
	}{
		{name: "DIR reference zero", data: []byte{0x10, 0}, dir: new(byte(0))},
		{name: "DIR reference with opaque remainder", data: []byte{0x10, 0x42, 0x73, 0}, dir: new(byte(0x42))},
		{name: "proprietary", data: []byte{0x42, 0x73}},
		{name: "reserved", data: []byte{0x81, 0x73, 0xff}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := protocol.ParseHistoricalBytes(test.data)
			if err != nil {
				t.Fatal(err)
			}

			want := protocol.HistoricalBytes{Raw: test.data, CategoryIndicator: test.data[0], DIRDataReference: test.dir}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("opaque historical bytes = %+v, want %+v", got, want)
			}
		})
	}
}

func TestEmptyHistoricalBytes(t *testing.T) {
	for _, data := range [][]byte{nil, {}} {
		got, err := protocol.ParseHistoricalBytes(data)
		if err != nil || !reflect.DeepEqual(got, protocol.HistoricalBytes{Raw: data}) {
			t.Errorf("empty historical bytes = %+v, %v", got, err)
		}
	}
}

func TestCardCapabilitiesThirdSoftwareFunctionTable(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
		want protocol.CardCapabilities
	}{
		{
			name: "OpenPGP flags", data: []byte{0xaa, 0xbb, 0xe0},
			want: protocol.CardCapabilities{
				Raw: [3]byte{0xaa, 0xbb, 0xe0}, CommandChaining: true, ExtendedLength: true,
				ExtendedLengthInformationInEFATRInfo: true, LogicalChannelAssignment: protocol.LogicalChannelAssignmentBasicOnly, MaxLogicalChannels: 1,
			},
		},
		{
			name: "interface assignment", data: []byte{0, 0, 9},
			want: protocol.CardCapabilities{Raw: [3]byte{0, 0, 9}, LogicalChannelAssignment: protocol.LogicalChannelAssignmentByInterfaceDevice, MaxLogicalChannels: 2},
		},
		{
			name: "card assignment", data: []byte{0, 0, 0x12},
			want: protocol.CardCapabilities{Raw: [3]byte{0, 0, 0x12}, LogicalChannelAssignment: protocol.LogicalChannelAssignmentByCard, MaxLogicalChannels: 3},
		},
		{
			name: "both assignments and eight or more channels", data: []byte{0, 0, 0x1f},
			want: protocol.CardCapabilities{Raw: [3]byte{0, 0, 0x1f}, LogicalChannelAssignment: protocol.LogicalChannelAssignmentByCardAndInterfaceDevice, MaxLogicalChannels: 8},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := protocol.ParseCardCapabilities(test.data)
			if err != nil || got != test.want {
				t.Errorf("capabilities = %+v, %v; want %+v", got, err, test.want)
			}
		})
	}
}

func TestCardServiceData(t *testing.T) {
	for _, test := range []struct {
		name string
		data byte
		want protocol.CardServiceData
	}{
		{
			name: "selection and GET DATA", data: 0xf4,
			want: protocol.CardServiceData{
				Raw: 0xf4, FullDFNameSelection: true, PartialDFNameSelection: true,
				EFDirDataObjects: true, EFATRInfoDataObjects: true, AccessServices: protocol.CardServiceAccessGetData, MasterFile: true,
			},
		},
		{name: "READ RECORDS", data: 0, want: protocol.CardServiceData{AccessServices: protocol.CardServiceAccessReadRecords, MasterFile: true}},
		{name: "READ BINARY", data: 8, want: protocol.CardServiceData{Raw: 8, AccessServices: protocol.CardServiceAccessReadBinary, MasterFile: true}},
		{name: "unknown access without MF", data: 0x0f, want: protocol.CardServiceData{Raw: 0x0f, AccessServices: 7}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := protocol.ParseCardServiceData([]byte{test.data})
			if err != nil || got != test.want {
				t.Errorf("service data = %+v, %v; want %+v", got, err, test.want)
			}
		})
	}
}

func TestMalformedHistoricalBytes(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "oversized", data: bytes.Repeat([]byte{0x80}, 16)},
		{name: "missing trailing status", data: []byte{0, 5, 0x90}},
		{name: "missing DIR reference", data: []byte{0x10}},
		{name: "truncated compact value", data: []byte{0x80, 0x73, 0, 0}},
		{name: "compact value overlaps trailing status", data: []byte{0, 0x73, 0, 0, 5, 0x90, 0}},
		{name: "short capabilities", data: []byte{0x80, 0x72, 0, 0}},
		{name: "empty service", data: []byte{0x80, 0x30}},
		{name: "duplicate service", data: []byte{0x80, 0x31, 0, 0x31, 0}},
		{name: "duplicate capabilities", data: []byte{0x80, 0x73, 0, 0, 0, 0x73, 0, 0, 0}},
		{name: "empty compact status", data: []byte{0x80, 0x80}},
		{name: "oversized compact status", data: []byte{0x80, 0x84, 1, 2, 3, 4}},
		{name: "nonfinal compact status", data: []byte{0x80, 0x81, 5, 0x31, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := protocol.ParseHistoricalBytes(test.data); !errors.Is(err, protocol.ErrInvalidResponse) {
				t.Errorf("error = %v, want ErrInvalidResponse", err)
			}
		})
	}

	for _, data := range [][]byte{nil, {0}, {0, 0}, {0, 0, 0, 0}} {
		if _, err := protocol.ParseCardCapabilities(data); !errors.Is(err, protocol.ErrInvalidResponse) {
			t.Errorf("capabilities %x error = %v, want ErrInvalidResponse", data, err)
		}
	}

	for _, data := range [][]byte{nil, {0, 0}} {
		if _, err := protocol.ParseCardServiceData(data); !errors.Is(err, protocol.ErrInvalidResponse) {
			t.Errorf("service %x error = %v, want ErrInvalidResponse", data, err)
		}
	}
}
