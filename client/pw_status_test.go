package client_test

import (
	"errors"
	"io"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestPutPWStatusBytes(t *testing.T) {
	for _, tt := range []struct {
		name   string
		update protocol.PWStatusBytesUpdate
		extend bool
		wire   []byte
	}{
		{
			name: "single signature policy",
			wire: []byte{0, 0xda, 0, 0xc4, 1, 0},
		},
		{
			name:   "multiple signature policy",
			update: protocol.PWStatusBytesUpdate{PW1ValidForMultipleSignatures: true},
			wire:   []byte{0, 0xda, 0, 0xc4, 1, 1},
		},
		{
			name: "extended policy", extend: true,
			update: protocol.PWStatusBytesUpdate{PW1ValidForMultipleSignatures: true},
			wire:   []byte{0, 0xda, 0, 0xc4, 0, 0, 1, 1},
		},
		{
			name: "full length and format",
			update: protocol.PWStatusBytesUpdate{
				PW1ValidForMultipleSignatures: true,
				LengthAndFormat: &protocol.PWLengthAndFormat{
					PW1MaxLength: 32, ResettingCodeMaxLength: 32, PW3MaxLength: 64,
					PW1PINBlock2: true, PW3PINBlock2: true,
				},
			},
			wire: []byte{0, 0xda, 0, 0xc4, 4, 1, 0xa0, 0x20, 0xc0},
		},
		{
			name: "extended full length and format", extend: true,
			update: protocol.PWStatusBytesUpdate{
				LengthAndFormat: &protocol.PWLengthAndFormat{
					PW1MaxLength: 32, ResettingCodeMaxLength: 48, PW3MaxLength: 64,
					PW1PINBlock2: true,
				},
			},
			wire: []byte{0, 0xda, 0, 0xc4, 0, 0, 4, 0, 0xa0, 0x30, 0x40},
		},
		{
			name: "present zero length and format",
			update: protocol.PWStatusBytesUpdate{
				PW1ValidForMultipleSignatures: true, LengthAndFormat: &protocol.PWLengthAndFormat{},
			},
			wire: []byte{0, 0xda, 0, 0xc4, 4, 1, 0, 0, 0},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var before protocol.PWLengthAndFormat
			if tt.update.LengthAndFormat != nil {
				before = *tt.update.LengthAndFormat
			}

			request := step{command: tt.wire, response: iso7816.Response{Status: 0x9000}}

			var c *client.Client
			if tt.extend {
				c = newExtendedClient(t, request)
			} else {
				c = newClient(t, request)
			}

			if err := c.PutPWStatusBytes(t.Context(), tt.update); err != nil {
				t.Fatal(err)
			}

			if tt.update.LengthAndFormat != nil && *tt.update.LengthAndFormat != before {
				t.Error("writing status bytes changed the borrowed length-and-format group")
			}
		})
	}
}

func TestPutPWStatusBytesErrorsDoNotRetry(t *testing.T) {
	for _, tt := range []struct {
		name     string
		response iso7816.Response
		ioError  error
		want     error
	}{
		{name: "four-byte form rejected", response: iso7816.Response{Status: 0x6a80}},
		{name: "PW3 required", response: iso7816.Response{Status: 0x6982}},
		{name: "transport", ioError: io.ErrUnexpectedEOF, want: io.ErrUnexpectedEOF},
		{name: "unexpected response data", response: iso7816.Response{Status: 0x9000, Data: []byte{1}}, want: protocol.ErrInvalidResponse},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newClient(t, step{
				command:  []byte{0, 0xda, 0, 0xc4, 4, 1, 0xa0, 0x20, 0xc0},
				response: tt.response, err: tt.ioError,
			})
			update := protocol.PWStatusBytesUpdate{
				PW1ValidForMultipleSignatures: true,
				LengthAndFormat: &protocol.PWLengthAndFormat{
					PW1MaxLength: 32, ResettingCodeMaxLength: 32, PW3MaxLength: 64,
					PW1PINBlock2: true, PW3PINBlock2: true,
				},
			}

			err := c.PutPWStatusBytes(t.Context(), update)

			if tt.want != nil {
				if !errors.Is(err, tt.want) {
					t.Errorf("error = %v, want %v", err, tt.want)
				}
			} else {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != tt.response.Status {
					t.Errorf("error = %v, want status %04x", err, tt.response.Status)
				}
			}
		})
	}
}

func TestPasswordCommandsUseExplicitPINBlock2Values(t *testing.T) {
	current, err := protocol.EncodePINBlock2("123456")
	if err != nil {
		t.Fatal(err)
	}

	replacement, err := protocol.EncodePINBlock2("654321")
	if err != nil {
		t.Fatal(err)
	}

	resettingCode, err := protocol.EncodePINBlock2("12345678")
	if err != nil {
		t.Fatal(err)
	}

	c := newClient(t,
		step{
			command:  []byte{0, 0x20, 0, 0x81, 8, 0x26, 0x12, 0x34, 0x56, 0xff, 0xff, 0xff, 0xff},
			response: iso7816.Response{Status: 0x9000},
		},
		step{
			command: []byte{0, 0x24, 0, 0x81, 16,
				0x26, 0x12, 0x34, 0x56, 0xff, 0xff, 0xff, 0xff,
				0x26, 0x65, 0x43, 0x21, 0xff, 0xff, 0xff, 0xff},
			response: iso7816.Response{Status: 0x9000},
		},
		step{
			command: []byte{0, 0x2c, 0, 0x81, 16,
				0x28, 0x12, 0x34, 0x56, 0x78, 0xff, 0xff, 0xff,
				0x26, 0x65, 0x43, 0x21, 0xff, 0xff, 0xff, 0xff},
			response: iso7816.Response{Status: 0x9000},
		},
		step{
			command:  []byte{0, 0x2c, 2, 0x81, 8, 0x26, 0x65, 0x43, 0x21, 0xff, 0xff, 0xff, 0xff},
			response: iso7816.Response{Status: 0x9000},
		},
	)

	if err := c.Verify(t.Context(), protocol.PW1Sign, current[:]); err != nil {
		t.Fatal(err)
	}

	if err := c.ChangeReferenceData(t.Context(), protocol.PW1Sign, current[:], replacement[:]); err != nil {
		t.Fatal(err)
	}

	if err := c.ResetRetryCounter(t.Context(), resettingCode[:], replacement[:]); err != nil {
		t.Fatal(err)
	}

	if err := c.ResetRetryCounterWithPW3(t.Context(), replacement[:]); err != nil {
		t.Fatal(err)
	}

	if current != [8]byte{0x26, 0x12, 0x34, 0x56, 0xff, 0xff, 0xff, 0xff} ||
		replacement != [8]byte{0x26, 0x65, 0x43, 0x21, 0xff, 0xff, 0xff, 0xff} ||
		resettingCode != [8]byte{0x28, 0x12, 0x34, 0x56, 0x78, 0xff, 0xff, 0xff} {
		t.Error("password commands changed borrowed PIN blocks")
	}
}
