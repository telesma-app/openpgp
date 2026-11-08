package client_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

func TestSelectAndGetData(t *testing.T) {
	data := []byte("https://example.org/key.asc")
	c := newClient(t,
		step{command: []byte{0, 0xa4, 4, 0, 6, 0xd2, 0x76, 0, 1, 0x24, 1, 0}, response: iso7816.Response{Status: 0x9000, Data: []byte{0x6f, 0}}},
		step{command: []byte{0, 0xca, 0x5f, 0x50, 0}, response: iso7816.Response{Status: 0x9000, Data: data}},
	)

	if err := c.Select(t.Context()); err != nil {
		t.Fatal(err)
	}

	got, err := c.GetData(t.Context(), protocol.URLObject)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, data) {
		t.Errorf("GET DATA = %q, want %q", got, data)
	}
}

func TestReadErrorIdentity(t *testing.T) {
	for _, tt := range []struct {
		name string
		step step
		want error
	}{
		{name: "transport", step: step{command: []byte{0, 0xca, 0x5f, 0x50, 0}, err: io.ErrUnexpectedEOF}, want: io.ErrUnexpectedEOF},
		{name: "APDU", step: step{command: []byte{0, 0xca, 0x5f, 0x50, 0}, response: iso7816.Response{Status: 0x6a88}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newClient(t, tt.step)

			_, err := c.GetData(t.Context(), protocol.URLObject)
			if tt.want != nil {
				if !errors.Is(err, tt.want) {
					t.Fatalf("error = %v, want %v", err, tt.want)
				}
			} else {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6a88 {
					t.Fatalf("APDU error = %v", err)
				}
			}
		})
	}
}

func TestGetNextData(t *testing.T) {
	for _, tt := range []struct {
		name     string
		response iso7816.Response
		err      error
	}{
		{name: "certificate", response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 1, 2}}},
		{name: "empty", response: iso7816.Response{Status: 0x9000}},
		{name: "unavailable", response: iso7816.Response{Status: 0x6a88}},
		{name: "transport", err: io.ErrUnexpectedEOF},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newClient(t, step{
				command: []byte{0, 0xcc, 0x7f, 0x21, 0}, response: tt.response, err: tt.err,
			})

			got, err := c.GetNextData(t.Context())

			switch {
			case tt.err != nil:
				if !errors.Is(err, tt.err) {
					t.Fatalf("error = %v, want %v", err, tt.err)
				}
			case tt.response.Status != 0x9000:
				var apduError *iso7816.APDUError
				if !errors.As(err, &apduError) || apduError.StatusWord() != tt.response.Status {
					t.Fatalf("error = %v, want APDU error %s", err, tt.response.Status)
				}
			default:
				if err != nil || !bytes.Equal(got, tt.response.Data) {
					t.Fatalf("certificate = %x, %v; want %x", got, err, tt.response.Data)
				}
			}
		})
	}
}

func TestPutDataAndSelectOccurrence(t *testing.T) {
	c := newClient(t,
		step{command: []byte{0, 0xa5, 2, 4, 6, 0x60, 4, 0x5c, 2, 0x7f, 0x21, 0}, response: iso7816.Response{Status: 0x9000, Data: []byte{0x60, 0}}},
		step{command: []byte{0, 0xda, 0x7f, 0x21, 3, 1, 2, 3}, response: iso7816.Response{Status: 0x9000}},
		step{command: []byte{0, 0xda, 0x5f, 0x50}, response: iso7816.Response{Status: 0x9000}},
	)
	if err := c.SelectData(t.Context(), protocol.CardholderCertificateObject, 2); err != nil {
		t.Fatal(err)
	}

	if err := c.PutData(t.Context(), protocol.CardholderCertificateObject, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}

	if err := c.PutData(t.Context(), protocol.URLObject, nil); err != nil {
		t.Fatal(err)
	}
}
