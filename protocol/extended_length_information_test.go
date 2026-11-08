package protocol_test

import (
	"errors"
	"testing"

	"github.com/telesma-app/openpgp/protocol"
)

func TestExtendedLengthInformation(t *testing.T) {
	for _, test := range []struct {
		name     string
		data     []byte
		command  uint16
		response uint16
	}{
		{
			name: "body", data: []byte{2, 2, 0x04, 0x00, 2, 2, 0x08, 0x00},
			command: 1024, response: 2048,
		},
		{
			name: "template", data: []byte{0x7f, 0x66, 8, 2, 2, 0x04, 0x00, 2, 2, 0x08, 0x00},
			command: 1024, response: 2048,
		},
		{
			name: "unsigned limits", data: []byte{2, 2, 0xff, 0xff, 2, 2, 0, 0},
			command: 65535,
		},
		{
			name: "long form lengths", data: []byte{2, 0x81, 2, 1, 0, 2, 0x82, 0, 2, 0, 0xff},
			command: 256, response: 255,
		},
		{
			name: "unknown DOs", data: []byte{0x7f, 0x74, 0, 2, 2, 0x04, 0x00, 0x80, 1, 0xff, 2, 2, 0x08, 0x00, 0x81, 0},
			command: 1024, response: 2048,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := protocol.ParseExtendedLengthInformation(test.data)
			if err != nil {
				t.Fatal(err)
			}

			if got.MaxCommandAPDULength != test.command || got.MaxResponseAPDULength != test.response {
				t.Errorf("lengths = %d, %d; want %d, %d", got.MaxCommandAPDULength, got.MaxResponseAPDULength, test.command, test.response)
			}

			if len(got.Raw) != len(test.data) || &got.Raw[0] != &test.data[0] {
				t.Error("Raw does not borrow the complete input")
			}
		})
	}
}

func TestExtendedLengthInformationMalformed(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "empty"},
		{name: "one INTEGER", data: []byte{2, 2, 1, 0}},
		{name: "command tag", data: []byte{3, 2, 1, 0, 2, 2, 1, 0}},
		{name: "response tag", data: []byte{2, 2, 1, 0, 3, 2, 1, 0}},
		{name: "command width", data: []byte{2, 1, 1, 2, 2, 1, 0}},
		{name: "response width", data: []byte{2, 2, 1, 0, 2, 3, 0, 1, 0}},
		{name: "truncated INTEGER", data: []byte{2, 2, 1, 0, 2, 2, 1}},
		{name: "third INTEGER", data: []byte{2, 2, 1, 0, 2, 2, 1, 0, 2, 2, 1, 0}},
		{name: "truncated template", data: []byte{0x7f, 0x66, 8, 2, 2, 1, 0}},
		{name: "trailing template data", data: []byte{0x7f, 0x66, 8, 2, 2, 1, 0, 2, 2, 1, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := protocol.ParseExtendedLengthInformation(test.data)

			if !errors.Is(err, protocol.ErrInvalidResponse) {
				t.Fatalf("error = %v, want ErrInvalidResponse", err)
			}
		})
	}
}
