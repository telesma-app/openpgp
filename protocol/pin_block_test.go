package protocol_test

import (
	"strings"
	"testing"

	"github.com/telesma-app/openpgp/protocol"
)

func TestEncodePINBlock2(t *testing.T) {
	// OpenPGP Card 3.4.1, Sec. 7.2.2, PIN block format 2 diagram:
	// C=2, N=4..12 in binary, decimal PIN nibbles, then F to 64 bits.
	for _, test := range []struct {
		name string
		pin  string
		want [8]byte
	}{
		{name: "four digits", pin: "1234", want: [8]byte{0x24, 0x12, 0x34, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{name: "odd length", pin: "12345", want: [8]byte{0x25, 0x12, 0x34, 0x5f, 0xff, 0xff, 0xff, 0xff}},
		{name: "leading zeros", pin: "000012", want: [8]byte{0x26, 0x00, 0x00, 0x12, 0xff, 0xff, 0xff, 0xff}},
		{name: "eight digits", pin: "12345678", want: [8]byte{0x28, 0x12, 0x34, 0x56, 0x78, 0xff, 0xff, 0xff}},
		{name: "ten digits", pin: "1234567890", want: [8]byte{0x2a, 0x12, 0x34, 0x56, 0x78, 0x90, 0xff, 0xff}},
		{name: "eleven digits", pin: "12345678901", want: [8]byte{0x2b, 0x12, 0x34, 0x56, 0x78, 0x90, 0x1f, 0xff}},
		{name: "twelve digits", pin: "123456789012", want: [8]byte{0x2c, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0xff}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := protocol.EncodePINBlock2(test.pin)
			if err != nil {
				t.Fatal(err)
			}

			if got != test.want {
				t.Errorf("PIN block = %x, want %x", got, test.want)
			}
		})
	}
}

func TestEncodePINBlock2RejectsInvalidInputWithoutPartialPIN(t *testing.T) {
	for _, test := range []struct {
		name string
		pin  string
	}{
		{name: "empty"},
		{name: "short", pin: "123"},
		{name: "long", pin: "1234567890123"},
		{name: "first non-digit", pin: "x23456"},
		{name: "last non-digit", pin: "12345x"},
		{name: "space", pin: "1234 6"},
		{name: "NUL", pin: "1234\x0056"},
		{name: "Arabic digits", pin: "١٢٣٤"},
		{name: "full-width digits", pin: "１２３"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := protocol.EncodePINBlock2(test.pin)
			if err == nil {
				t.Fatal("invalid PIN was accepted")
			}

			if got != ([8]byte{}) {
				t.Errorf("error returned a partial PIN block: %x", got)
			}

			if test.pin != "" && strings.Contains(err.Error(), test.pin) {
				t.Error("error contains the supplied PIN")
			}
		})
	}
}
