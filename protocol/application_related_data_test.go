package protocol_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/openpgp/protocol"
)

func TestApplicationRelatedData(t *testing.T) {
	aid := []byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 6, 0x12, 0x34, 0x56, 0x78, 0, 0}
	capabilities := []byte{0xff, 3, 0, 32, 8, 0, 1, 0, 1, 1}
	rsa := []byte{1, 8, 0, 0, 32, 0}
	p256 := []byte{19, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7}
	ed25519 := []byte{22, 0x2b, 0x06, 1, 4, 1, 0xda, 0x47, 0x0f, 1, 0xff}
	fingerprints := bytes.Repeat([]byte{0xa5}, 60)
	caFingerprints := bytes.Repeat([]byte{0x5a}, 60)

	var discretionary []byte
	for _, field := range []struct {
		tag   uint32
		value []byte
	}{
		{0xc0, capabilities}, {0xc1, rsa}, {0xc2, p256}, {0xc3, ed25519},
		{0xc4, []byte{1, 0xa0, 32, 0xc0, 3, 0, 2}},
		{0xc5, fingerprints}, {0xc6, caFingerprints},
		{0xcd, []byte{0, 0, 0, 1, 0x65, 0x53, 0xf1, 0, 0xff, 0xff, 0xff, 0xff}},
	} {
		discretionary = bertlv.Append(discretionary, field.tag, field.value)
	}

	data := bertlv.Append(nil, 0x4f, aid)
	data = bertlv.Append(data, 0x5f52, []byte{0, 0x73, 0, 0, 0xe0, 5, 0x90, 0})
	data = bertlv.Append(data, 0x73, discretionary)
	data = bertlv.Append(data, 0x7f66, []byte{2, 2, 0x0b, 0xfe, 2, 2, 0x0b, 0xfe})
	data = bertlv.Append(data, 0x7f74, []byte{0x81, 1, 0x20})

	got, err := protocol.ParseApplicationRelatedData(bertlv.Append(nil, 0x6e, data))
	if err != nil {
		t.Fatal(err)
	}

	if got.AID.String() != "D2760001240103040006123456780000" || got.AID.VersionMajor != 3 || got.AID.VersionMinor != 4 || got.AID.Manufacturer != 6 || got.AID.SerialNumber != 0x12345678 {
		t.Errorf("AID = %+v", got.AID)
	}

	c := got.ExtendedCapabilities
	if c == nil || !c.SecureMessaging || !c.GetChallenge || !c.KeyImport || !c.PWStatusBytesChangeable || !c.PrivateUseObjects || !c.AlgorithmAttributesChangeable || !c.AES || !c.KDF || c.MaxChallengeLength != 32 || c.MaxCertificateLength != 2048 || c.MaxSpecialObjectLength != 256 || !c.PINBlock2 || !c.ManageSecurityEnvironment {
		t.Errorf("capabilities = %+v", c)
	}

	if got.SignatureAlgorithmAttributes.ModulusBits != 2048 || got.SignatureAlgorithmAttributes.ExponentBits != 32 || got.DecryptionAlgorithmAttributes.Algorithm != protocol.ECDSA || got.AuthenticationAlgorithmAttributes.ImportFormat != protocol.ImportFormatStandardWithPublicKey || !bytes.Equal(got.AuthenticationAlgorithmAttributes.CurveOID, ed25519[1:10]) {
		t.Errorf("algorithms = %+v / %+v / %+v", got.SignatureAlgorithmAttributes, got.DecryptionAlgorithmAttributes, got.AuthenticationAlgorithmAttributes)
	}

	wantStatus := protocol.PWStatusBytes{
		PW1ValidForMultipleSignatures: true, PW1MaxLength: 32, ResettingCodeMaxLength: 32,
		PW3MaxLength: 64, PW1PINBlock2: true, PW3PINBlock2: true, PW1Retries: 3, PW3Retries: 2,
	}
	if got.PWStatusBytes == nil || *got.PWStatusBytes != wantStatus {
		t.Errorf("password status = %+v, want %+v", got.PWStatusBytes, wantStatus)
	}

	fingerprint := [20]byte(fingerprints[:20])
	if !reflect.DeepEqual(got.Fingerprints, [][20]byte{fingerprint, fingerprint, fingerprint}) {
		t.Errorf("fingerprints = %x, want three %x entries", got.Fingerprints, fingerprint)
	}

	caFingerprint := [20]byte(caFingerprints[:20])
	if !reflect.DeepEqual(got.CAFingerprints, [][20]byte{caFingerprint, caFingerprint, caFingerprint}) {
		t.Errorf("CA fingerprints = %x, want three %x entries", got.CAFingerprints, caFingerprint)
	}

	if !reflect.DeepEqual(got.KeyGenerationTimes, []uint32{1, 1700000000, 0xffffffff}) {
		t.Errorf("key generation times = %+v", got.KeyGenerationTimes)
	}

	if got.HistoricalBytes == nil || got.HistoricalBytes.CardCapabilities == nil ||
		!got.HistoricalBytes.CardCapabilities.CommandChaining || !got.HistoricalBytes.CardCapabilities.ExtendedLength ||
		got.HistoricalBytes.LifeCycleStatus == nil || *got.HistoricalBytes.LifeCycleStatus != 5 {
		t.Errorf("historical bytes = %+v", got.HistoricalBytes)
	}

	if got.ExtendedLengthInformation == nil || got.ExtendedLengthInformation.MaxCommandAPDULength != 3070 || got.ExtendedLengthInformation.MaxResponseAPDULength != 3070 {
		t.Errorf("extended length information = %+v", got.ExtendedLengthInformation)
	}

	if got.GeneralFeatureManagement == nil || got.GeneralFeatureManagement.Features != protocol.GeneralFeatureButton {
		t.Errorf("general feature management = %+v", got.GeneralFeatureManagement)
	}
}

func TestApplicationRelatedDataOmittedFields(t *testing.T) {
	data := bertlv.Append(nil, 0x4f, []byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 6, 0, 0, 0, 0, 0, 0})

	got, err := protocol.ParseApplicationRelatedData(data)
	if err != nil {
		t.Fatal(err)
	}

	if got.ExtendedCapabilities != nil || got.PWStatusBytes != nil || got.SignatureAlgorithmAttributes.Algorithm != 0 ||
		got.HistoricalBytes != nil || got.ExtendedLengthInformation != nil || got.GeneralFeatureManagement != nil {
		t.Errorf("missing optional fields = %+v", got)
	}

	if got.Fingerprints != nil || got.CAFingerprints != nil {
		t.Errorf("omitted fingerprints = %x / %x, want nil lists", got.Fingerprints, got.CAFingerprints)
	}
}

func TestApplicationRelatedDataFingerprints(t *testing.T) {
	const (
		fingerprintWire = "SIG fingerprint 0001" + "DEC fingerprint 0002" +
			"AUT fingerprint 0003" + "VND fingerprint 0004"
		caFingerprintWire = "CA SIG fingerprint 1" + "CA DEC fingerprint 2" +
			"CA AUT fingerprint 3" + "CA VND fingerprint 4"
	)

	for _, test := range []struct {
		name   string
		length int
		count  int
	}{
		{name: "standard slots", length: 60, count: 3},
		{name: "vendor slot", length: 80, count: 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			discretionary := bertlv.Append(nil, 0xc5, []byte(fingerprintWire[:test.length]))
			discretionary = bertlv.Append(discretionary, 0xc6, []byte(caFingerprintWire[:test.length]))
			data := bertlv.Append(nil, 0x4f, []byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 6, 0, 0, 0, 0, 0, 0})
			data = bertlv.Append(data, 0x73, discretionary)
			wantFingerprints := [][20]byte{
				[20]byte([]byte("SIG fingerprint 0001")),
				[20]byte([]byte("DEC fingerprint 0002")),
				[20]byte([]byte("AUT fingerprint 0003")),
				[20]byte([]byte("VND fingerprint 0004")),
			}
			wantCAFingerprints := [][20]byte{
				[20]byte([]byte("CA SIG fingerprint 1")),
				[20]byte([]byte("CA DEC fingerprint 2")),
				[20]byte([]byte("CA AUT fingerprint 3")),
				[20]byte([]byte("CA VND fingerprint 4")),
			}

			got, err := protocol.ParseApplicationRelatedData(data)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(got.Fingerprints, wantFingerprints[:test.count]) {
				t.Errorf("fingerprints = %x, want %x", got.Fingerprints, wantFingerprints[:test.count])
			}

			if !reflect.DeepEqual(got.CAFingerprints, wantCAFingerprints[:test.count]) {
				t.Errorf("CA fingerprints = %x, want %x", got.CAFingerprints, wantCAFingerprints[:test.count])
			}
		})
	}
}

func TestApplicationRelatedDataUnspecifiedFingerprints(t *testing.T) {
	discretionary := bertlv.Append(nil, 0xc5, make([]byte, 60))
	discretionary = bertlv.Append(discretionary, 0xc6, make([]byte, 60))
	data := bertlv.Append(nil, 0x4f, []byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 6, 0, 0, 0, 0, 0, 0})
	data = bertlv.Append(data, 0x73, discretionary)
	want := make([][20]byte, 3)

	got, err := protocol.ParseApplicationRelatedData(data)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(got.Fingerprints, want) || !reflect.DeepEqual(got.CAFingerprints, want) {
		t.Errorf("unspecified fingerprints = %x / %x, want three zero entries in each list", got.Fingerprints, got.CAFingerprints)
	}
}

func TestApplicationRelatedDataFingerprintLengths(t *testing.T) {
	for _, object := range []struct {
		name string
		tag  uint32
	}{
		{name: "fingerprints", tag: 0xc5},
		{name: "CA fingerprints", tag: 0xc6},
	} {
		t.Run(object.name, func(t *testing.T) {
			for _, test := range []struct {
				name   string
				length int
			}{
				{name: "empty"},
				{name: "below minimum", length: 40},
				{name: "partial entry", length: 61},
			} {
				t.Run(test.name, func(t *testing.T) {
					discretionary := bertlv.Append(nil, object.tag, make([]byte, test.length))
					data := bertlv.Append(nil, 0x4f, []byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 6, 0, 0, 0, 0, 0, 0})
					data = bertlv.Append(data, 0x73, discretionary)

					_, err := protocol.ParseApplicationRelatedData(data)
					if !errors.Is(err, protocol.ErrInvalidResponse) {
						t.Errorf("error = %v, want ErrInvalidResponse", err)
					}
				})
			}
		})
	}
}

func TestApplicationRelatedDataPresentEmptyMetadata(t *testing.T) {
	data := bertlv.Append(nil, 0x4f, []byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 6, 0, 0, 0, 0, 0, 0})
	data = bertlv.Append(data, 0x5f52, nil)
	data = bertlv.Append(data, 0x7f66, []byte{2, 2, 0, 0, 2, 2, 0, 0})
	data = bertlv.Append(data, 0x7f74, []byte{0x81, 1, 0})

	got, err := protocol.ParseApplicationRelatedData(data)
	if err != nil {
		t.Fatal(err)
	}

	if got.HistoricalBytes == nil || got.HistoricalBytes.Raw == nil || len(got.HistoricalBytes.Raw) != 0 {
		t.Errorf("present empty historical bytes = %+v", got.HistoricalBytes)
	}

	if got.ExtendedLengthInformation == nil || got.ExtendedLengthInformation.MaxCommandAPDULength != 0 || got.ExtendedLengthInformation.MaxResponseAPDULength != 0 {
		t.Errorf("present zero lengths = %+v", got.ExtendedLengthInformation)
	}

	if got.GeneralFeatureManagement == nil || got.GeneralFeatureManagement.Features != 0 {
		t.Errorf("present zero feature flags = %+v", got.GeneralFeatureManagement)
	}
}

func TestApplicationRelatedDataMalformed(t *testing.T) {
	aid := []byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 6, 0, 0, 0, 0, 0, 0}

	withFields := func(fields []byte) []byte {
		return append(bertlv.Append(nil, 0x4f, aid), fields...)
	}

	withDiscretionary := func(data []byte) []byte {
		return bertlv.Append(withFields(nil), 0x73, data)
	}
	for name, data := range map[string][]byte{
		"empty response":            {},
		"missing AID":               {0x6e, 0},
		"trailing outer data":       append(bertlv.Append(nil, 0x6e, withFields(nil)), 0x73, 0),
		"truncated TLV":             withFields([]byte{0x73, 2, 0xc0}),
		"duplicate discretionary":   withFields([]byte{0x73, 0, 0x73, 0}),
		"short AID":                 {0x4f, 1, 0xd2},
		"wrong AID":                 bertlv.Append(nil, 0x4f, make([]byte, 16)),
		"short capabilities":        withDiscretionary([]byte{0xc0, 1, 0}),
		"short fingerprint list":    withDiscretionary([]byte{0xc5, 1, 0}),
		"short generation times":    withDiscretionary([]byte{0xcd, 1, 0}),
		"duplicate password status": withDiscretionary([]byte{0xc4, 7, 0, 32, 32, 32, 3, 0, 3, 0xc4, 7, 0, 32, 32, 32, 3, 0, 3}),
		"short historical status":   bertlv.Append(bertlv.Append(nil, 0x4f, aid), 0x5f52, []byte{0, 5, 0x90}),
		"missing response length":   bertlv.Append(bertlv.Append(nil, 0x4f, aid), 0x7f66, []byte{2, 2, 8, 0}),
		"empty feature flags":       bertlv.Append(bertlv.Append(nil, 0x4f, aid), 0x7f74, []byte{0x81, 0}),
		"nested incomplete lengths": withDiscretionary(bertlv.Append(nil, 0x7f66, []byte{2, 2, 8, 0})),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := protocol.ParseApplicationRelatedData(data)
			if !errors.Is(err, protocol.ErrInvalidResponse) {
				t.Errorf("error = %v", err)
			}
		})
	}
}

func TestCapturedApplicationMetadata(t *testing.T) {
	// Captures from the attached USB and contactless cards. Serial numbers,
	// fingerprints, and generation timestamps have been zeroed in the fixtures.
	for _, tc := range []struct {
		file          string
		keyCount      int
		importType    protocol.ImportFormat
		maxAPDULength uint16
	}{
		{"usb-application.hex", 4, protocol.ImportFormatStandard, 3070},
		{"contactless-application.hex", 3, protocol.ImportFormatCRTWithModulus, 2048},
	} {
		t.Run(tc.file, func(t *testing.T) {
			encoded, err := os.ReadFile(filepath.Join("testdata", tc.file))
			if err != nil {
				t.Fatal(err)
			}

			data, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
			if err != nil {
				t.Fatal(err)
			}

			got, err := protocol.ParseApplicationRelatedData(data)
			if err != nil {
				t.Fatal(err)
			}

			if got.AID.VersionMajor != 3 || got.AID.VersionMinor != 4 || got.SignatureAlgorithmAttributes.ModulusBits != 2048 || got.SignatureAlgorithmAttributes.ImportFormat != tc.importType {
				t.Errorf("AID/algorithm = %+v / %+v", got.AID, got.SignatureAlgorithmAttributes)
			}

			if len(got.Fingerprints) != tc.keyCount || len(got.CAFingerprints) != tc.keyCount || len(got.KeyGenerationTimes) != tc.keyCount || len(got.KeyInformation) != tc.keyCount {
				t.Errorf("key counts = %d/%d/%d/%d, want %d", len(got.Fingerprints), len(got.CAFingerprints), len(got.KeyGenerationTimes), len(got.KeyInformation), tc.keyCount)
			}

			if got.ExtendedLengthInformation == nil || got.ExtendedLengthInformation.MaxCommandAPDULength != tc.maxAPDULength || got.ExtendedLengthInformation.MaxResponseAPDULength != tc.maxAPDULength {
				t.Errorf("extended length information = %+v, want %d-byte APDUs", got.ExtendedLengthInformation, tc.maxAPDULength)
			}

			if got.GeneralFeatureManagement == nil || got.GeneralFeatureManagement.Features != protocol.GeneralFeatureButton {
				t.Errorf("general feature management = %+v, want button", got.GeneralFeatureManagement)
			}

			for _, flag := range []*protocol.UserInteractionFlag{got.SignatureUIF, got.DecryptionUIF, got.AuthenticationUIF} {
				if flag == nil || flag.State != protocol.UIFDisabled || flag.Features != protocol.GeneralFeatureButton {
					t.Errorf("captured UIF = %+v, want disabled with button", flag)
				}
			}

			if got.HistoricalBytes == nil || got.HistoricalBytes.CardCapabilities == nil ||
				!got.HistoricalBytes.CardCapabilities.CommandChaining || !got.HistoricalBytes.CardCapabilities.ExtendedLength ||
				got.HistoricalBytes.LifeCycleStatus == nil || *got.HistoricalBytes.LifeCycleStatus != 5 ||
				got.HistoricalBytes.StatusWord == nil || *got.HistoricalBytes.StatusWord != 0x9000 {
				t.Errorf("historical bytes = %+v", got.HistoricalBytes)
			}
		})
	}
}
