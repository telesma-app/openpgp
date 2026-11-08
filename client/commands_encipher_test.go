package client_test

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/transport"
)

func TestEncipherWire(t *testing.T) {
	for _, tt := range []struct {
		name     string
		extended bool
		length   int
		header   []byte
		le       []byte
	}{
		{
			name:   "short one block",
			length: 16,
			header: []byte{0, 0x2a, 0x86, 0x80, 0x10},
			le:     []byte{0},
		},
		{
			name:   "short two blocks",
			length: 32,
			header: []byte{0, 0x2a, 0x86, 0x80, 0x20},
			le:     []byte{0},
		},
		{
			name:     "extended one block",
			extended: true,
			length:   16,
			header:   []byte{0, 0x2a, 0x86, 0x80, 0, 0, 0x10},
			le:       []byte{0, 0},
		},
		{
			name:     "extended two blocks",
			extended: true,
			length:   32,
			header:   []byte{0, 0x2a, 0x86, 0x80, 0, 0, 0x20},
			le:       []byte{0, 0},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := bytes.Repeat([]byte{0x42}, tt.length)
			want := slices.Concat([]byte{2}, bytes.Repeat([]byte{0xa5}, tt.length))
			s := step{
				command:  slices.Concat(tt.header, input, tt.le),
				response: iso7816.Response{Status: 0x9000, Data: want},
			}

			var c *client.Client
			if tt.extended {
				c = newExtendedClient(t, s)
			} else {
				c = newClient(t, s)
			}

			got, err := c.Encipher(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got, want) {
				t.Errorf("enciphered data = %x, want %x including padding indicator", got, want)
			}
		})
	}
}

func TestEncipherFailureDoesNotRetry(t *testing.T) {
	for _, tt := range []struct {
		name     string
		response iso7816.Response
		err      error
	}{
		{name: "APDU", response: iso7816.Response{Status: 0x6982}},
		{name: "transport", err: &transport.DeviceInvalidatedError{Err: io.ErrUnexpectedEOF}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := bytes.Repeat([]byte{0x42}, 16)
			c := newClient(t, step{
				command:  slices.Concat([]byte{0, 0x2a, 0x86, 0x80, 0x10}, input, []byte{0}),
				response: tt.response,
				err:      tt.err,
			})

			got, err := c.Encipher(t.Context(), input)

			if got != nil {
				t.Errorf("enciphered data on failure = %x, want nil", got)
			}

			if tt.err != nil {
				var invalidated *transport.DeviceInvalidatedError
				if !errors.As(err, &invalidated) || !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("error = %v, want invalidation with original cause", err)
				}
			} else {
				var apduError *iso7816.APDUError
				if !errors.As(err, &apduError) || apduError.StatusWord() != 0x6982 {
					t.Fatalf("error = %v, want APDU error 6982", err)
				}
			}
		})
	}
}
