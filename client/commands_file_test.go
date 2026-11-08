package client_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestGetDataOddWireAndOpaqueResponse(t *testing.T) {
	data := []byte{0x61, 0x81, 0xff, 0x7f}

	for _, test := range []struct {
		name     string
		file     protocol.FileID
		extended bool
		command  []byte
	}{
		{
			name: "EF.DIR short", file: protocol.DirectoryFile,
			command: []byte{0, 0xcb, 0x2f, 0, 2, 0x5c, 0, 0},
		},
		{
			name: "EF.ATR/INFO short", file: protocol.ATRInfoFile,
			command: []byte{0, 0xcb, 0x2f, 1, 2, 0x5c, 0, 0},
		},
		{
			name: "EF.DIR extended", file: protocol.DirectoryFile, extended: true,
			command: []byte{0, 0xcb, 0x2f, 0, 0, 0, 2, 0x5c, 0, 0, 0},
		},
		{
			name: "EF.ATR/INFO extended", file: protocol.ATRInfoFile, extended: true,
			command: []byte{0, 0xcb, 0x2f, 1, 0, 0, 2, 0x5c, 0, 0, 0},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := step{command: test.command, response: iso7816.Response{Status: 0x9000, Data: data}}

			var c *client.Client
			if test.extended {
				c = newExtendedClient(t, request)
			} else {
				c = newClient(t, request)
			}

			got, err := c.GetDataOdd(t.Context(), test.file)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got, data) {
				t.Errorf("file contents = %x, want unchanged %x", got, data)
			}
		})
	}
}

func TestGetDataOddFailureIdentityWithoutRetry(t *testing.T) {
	for _, test := range []struct {
		name     string
		response iso7816.Response
		err      error
	}{
		{name: "file absent", response: iso7816.Response{Status: 0x6a82}},
		{name: "instruction unsupported", response: iso7816.Response{Status: 0x6d00}},
		{name: "transport failure", err: io.ErrUnexpectedEOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := newClient(t, step{
				command:  []byte{0, 0xcb, 0x2f, 0, 2, 0x5c, 0, 0},
				response: test.response, err: test.err,
			})

			data, err := c.GetDataOdd(t.Context(), protocol.DirectoryFile)

			if data != nil || err == nil {
				t.Fatalf("GetDataOdd = %x, %v; want failure without contents", data, err)
			}

			if test.err != nil {
				if !errors.Is(err, test.err) {
					t.Errorf("error = %v, want transport cause %v", err, test.err)
				}
			} else {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != test.response.Status {
					t.Errorf("error = %v, want APDU status %s", err, test.response.Status)
				}
			}
		})
	}
}
