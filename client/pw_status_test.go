package client_test

import (
	"errors"
	"io"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestGetPWStatusBytes(t *testing.T) {
	for _, test := range []struct {
		name string
		new  func(*testing.T, ...step) *client.Client
		wire []byte
	}{
		{name: "short", new: newClient, wire: []byte{0, 0xca, 0, 0xc4, 0}},
		{name: "extended", new: newExtendedClient, wire: []byte{0, 0xca, 0, 0xc4, 0, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := []byte{1, 0xa0, 0xfe, 0xc0, 3, 2, 1}
			c := test.new(t, step{command: test.wire, response: iso7816.Response{Status: 0x9000, Data: data}})
			want := protocol.PWStatusBytes{
				PW1ValidForMultipleSignatures: true, PW1MaxLength: 32, ResettingCodeMaxLength: 254,
				PW3MaxLength: 64, PW1PINBlock2: true, PW3PINBlock2: true,
				PW1Retries: 3, ResettingCodeRetries: 2, PW3Retries: 1,
			}

			got, err := c.GetPWStatusBytes(t.Context())
			if err != nil || got != want {
				t.Errorf("password status bytes = %+v, %v; want %+v, nil", got, err, want)
			}
		})
	}
}

func TestGetPWStatusBytesErrors(t *testing.T) {
	for _, test := range []struct {
		name     string
		response iso7816.Response
		ioError  error
		want     error
	}{
		{name: "unavailable", response: iso7816.Response{Status: 0x6a88}},
		{name: "transport", ioError: io.ErrUnexpectedEOF, want: io.ErrUnexpectedEOF},
		{name: "malformed", response: iso7816.Response{Status: 0x9000, Data: []byte{1, 0xa0, 0xfe, 0xc0, 3, 2}}, want: protocol.ErrInvalidResponse},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := newClient(t, step{command: []byte{0, 0xca, 0, 0xc4, 0}, response: test.response, err: test.ioError})

			got, err := c.GetPWStatusBytes(t.Context())
			if got != (protocol.PWStatusBytes{}) {
				t.Errorf("password status bytes = %+v, want zero result", got)
			}

			if test.want != nil {
				if !errors.Is(err, test.want) {
					t.Errorf("error = %v, want %v", err, test.want)
				}
			} else {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != test.response.Status {
					t.Errorf("error = %v, want APDU error %s", err, test.response.Status)
				}
			}
		})
	}
}

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
