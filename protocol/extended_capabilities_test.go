package protocol_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/telesma-app/openpgp/protocol"
)

func TestParseExtendedCapabilities(t *testing.T) {
	for _, test := range []struct {
		name string
		data [10]byte
		want protocol.ExtendedCapabilities
	}{
		{name: "zero values"},
		{
			name: "secure messaging bit", data: [10]byte{0x80},
			want: protocol.ExtendedCapabilities{SecureMessaging: true},
		},
		{
			name: "get challenge bit", data: [10]byte{0x40},
			want: protocol.ExtendedCapabilities{GetChallenge: true},
		},
		{
			name: "key import bit", data: [10]byte{0x20},
			want: protocol.ExtendedCapabilities{KeyImport: true},
		},
		{
			name: "password status changeable bit", data: [10]byte{0x10},
			want: protocol.ExtendedCapabilities{PWStatusBytesChangeable: true},
		},
		{
			name: "private use objects bit", data: [10]byte{0x08},
			want: protocol.ExtendedCapabilities{PrivateUseObjects: true},
		},
		{
			name: "algorithm attributes changeable bit", data: [10]byte{0x04},
			want: protocol.ExtendedCapabilities{AlgorithmAttributesChangeable: true},
		},
		{
			name: "AES bit", data: [10]byte{0x02},
			want: protocol.ExtendedCapabilities{AES: true},
		},
		{
			name: "KDF bit", data: [10]byte{0x01},
			want: protocol.ExtendedCapabilities{KDF: true},
		},
		{
			name: "all capability bits", data: [10]byte{0xff},
			want: protocol.ExtendedCapabilities{
				SecureMessaging: true, GetChallenge: true, KeyImport: true, PWStatusBytesChangeable: true,
				PrivateUseObjects: true, AlgorithmAttributesChangeable: true, AES: true, KDF: true,
			},
		},
		{
			name: "AES-128 secure messaging", data: [10]byte{0x80, 1},
			want: protocol.ExtendedCapabilities{SecureMessaging: true, SecureMessagingAlgorithm: protocol.SecureMessagingAES128},
		},
		{
			name: "AES-256 secure messaging", data: [10]byte{0x80, 2},
			want: protocol.ExtendedCapabilities{SecureMessaging: true, SecureMessagingAlgorithm: protocol.SecureMessagingAES256},
		},
		{
			name: "SCP11b secure messaging", data: [10]byte{0x80, 3},
			want: protocol.ExtendedCapabilities{SecureMessaging: true, SecureMessagingAlgorithm: protocol.SecureMessagingSCP11b},
		},
		{
			name: "unknown secure messaging algorithm", data: [10]byte{0x80, 0x7f},
			want: protocol.ExtendedCapabilities{SecureMessaging: true, SecureMessagingAlgorithm: 0x7f},
		},
		{
			name: "algorithm without secure messaging bit", data: [10]byte{1: 2},
			want: protocol.ExtendedCapabilities{SecureMessagingAlgorithm: protocol.SecureMessagingAES256},
		},
		{
			name: "distinct big-endian lengths", data: [10]byte{2: 0x12, 3: 0x34, 4: 0x56, 5: 0x78, 6: 0x9a, 7: 0xbc},
			want: protocol.ExtendedCapabilities{MaxChallengeLength: 0x1234, MaxCertificateLength: 0x5678, MaxSpecialObjectLength: 0x9abc},
		},
		{
			name: "unsigned length limits", data: [10]byte{2: 0xff, 3: 0xff, 4: 0x80, 5: 1, 7: 1},
			want: protocol.ExtendedCapabilities{MaxChallengeLength: 65535, MaxCertificateLength: 32769, MaxSpecialObjectLength: 1},
		},
		{
			name: "PIN block 2 only", data: [10]byte{8: 1},
			want: protocol.ExtendedCapabilities{PINBlock2: true},
		},
		{
			name: "MSE only", data: [10]byte{9: 1},
			want: protocol.ExtendedCapabilities{ManageSecurityEnvironment: true},
		},
		{
			name: "PIN block 2 and MSE", data: [10]byte{8: 1, 9: 1},
			want: protocol.ExtendedCapabilities{PINBlock2: true, ManageSecurityEnvironment: true},
		},
		{name: "reserved PIN block format", data: [10]byte{8: 2}},
		{name: "reserved MSE value", data: [10]byte{9: 0xff}},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := test.data
			want := test.want
			want.Raw = test.data[:]

			got, err := protocol.ParseExtendedCapabilities(data[:])
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(got, want) {
				t.Errorf("capabilities = %+v, want %+v", got, want)
			}

			if data != test.data {
				t.Error("parsing changed the input")
			}

			if len(got.Raw) != len(data) || &got.Raw[0] != &data[0] {
				t.Error("Raw does not borrow the complete input")
			}
		})
	}
}

func TestParseExtendedCapabilitiesInvalidLength(t *testing.T) {
	for _, test := range []struct {
		name   string
		length int
	}{
		{name: "empty"},
		{name: "truncated", length: 9},
		{name: "trailing byte", length: 11},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := protocol.ParseExtendedCapabilities(make([]byte, test.length))
			if !errors.Is(err, protocol.ErrInvalidResponse) {
				t.Errorf("error = %v, want ErrInvalidResponse", err)
			}

			if !reflect.DeepEqual(got, protocol.ExtendedCapabilities{}) {
				t.Errorf("capabilities = %+v, want zero result", got)
			}
		})
	}
}
