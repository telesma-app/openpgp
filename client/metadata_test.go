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

func TestGetHistoricalBytes(t *testing.T) {
	data := []byte{0, 0x73, 0, 0, 0xe0, 5, 0x90, 0}

	for _, test := range []struct {
		name string
		new  func(*testing.T, ...step) *client.Client
		wire []byte
	}{
		{name: "short", new: newClient, wire: []byte{0, 0xca, 0x5f, 0x52, 0}},
		{name: "extended", new: newExtendedClient, wire: []byte{0, 0xca, 0x5f, 0x52, 0, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := test.new(t, step{command: test.wire, response: iso7816.Response{Status: 0x9000, Data: data}})

			got, err := c.GetHistoricalBytes(t.Context())
			if err != nil {
				t.Fatal(err)
			}

			capabilities := got.CardCapabilities
			if got.CategoryIndicator != 0 || capabilities == nil || !capabilities.CommandChaining ||
				!capabilities.ExtendedLength || !capabilities.ExtendedLengthInformationInEFATRInfo ||
				got.LifeCycleStatus == nil || *got.LifeCycleStatus != 5 || got.StatusWord == nil || *got.StatusWord != 0x9000 {
				t.Errorf("historical bytes = %+v, capabilities %+v", got, capabilities)
			}

			if !bytes.Equal(got.Raw, data) {
				t.Errorf("historical bytes Raw = %x, want %x", got.Raw, data)
			}
		})
	}
}

func TestGetExtendedLengthInformation(t *testing.T) {
	data := []byte{0x7f, 0x66, 8, 2, 2, 0x0b, 0xfe, 2, 2, 0x0b, 0xfe}

	for _, test := range []struct {
		name string
		new  func(*testing.T, ...step) *client.Client
		wire []byte
	}{
		{name: "short", new: newClient, wire: []byte{0, 0xca, 0x7f, 0x66, 0}},
		{name: "extended", new: newExtendedClient, wire: []byte{0, 0xca, 0x7f, 0x66, 0, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := test.new(t, step{command: test.wire, response: iso7816.Response{Status: 0x9000, Data: data}})

			got, err := c.GetExtendedLengthInformation(t.Context())
			if err != nil {
				t.Fatal(err)
			}

			if got.MaxCommandAPDULength != 3070 || got.MaxResponseAPDULength != 3070 || !bytes.Equal(got.Raw, data) {
				t.Errorf("extended length information = %+v, want 3070-byte APDU limits", got)
			}
		})
	}
}

func TestGetGeneralFeatureManagement(t *testing.T) {
	data := []byte{0x7f, 0x74, 3, 0x81, 1, 0x20}

	for _, test := range []struct {
		name string
		new  func(*testing.T, ...step) *client.Client
		wire []byte
	}{
		{name: "short", new: newClient, wire: []byte{0, 0xca, 0x7f, 0x74, 0}},
		{name: "extended", new: newExtendedClient, wire: []byte{0, 0xca, 0x7f, 0x74, 0, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := test.new(t, step{command: test.wire, response: iso7816.Response{Status: 0x9000, Data: data}})

			got, err := c.GetGeneralFeatureManagement(t.Context())
			if err != nil {
				t.Fatal(err)
			}

			if got.Features != protocol.GeneralFeatureButton || !bytes.Equal(got.Raw, data) {
				t.Errorf("general feature management = %+v, want Button", got)
			}
		})
	}
}

func TestMetadataReadErrors(t *testing.T) {
	for _, operation := range []struct {
		name      string
		wire      []byte
		malformed []byte
		read      func(*client.Client) error
	}{
		{
			name: "historical bytes", wire: []byte{0, 0xca, 0x5f, 0x52, 0}, malformed: []byte{0, 0x73},
			read: func(c *client.Client) error { _, err := c.GetHistoricalBytes(t.Context()); return err },
		},
		{
			name: "extended length information", wire: []byte{0, 0xca, 0x7f, 0x66, 0}, malformed: []byte{2, 2, 8},
			read: func(c *client.Client) error { _, err := c.GetExtendedLengthInformation(t.Context()); return err },
		},
		{
			name: "general feature management", wire: []byte{0, 0xca, 0x7f, 0x74, 0}, malformed: []byte{0x81, 2, 0x20},
			read: func(c *client.Client) error { _, err := c.GetGeneralFeatureManagement(t.Context()); return err },
		},
	} {
		for _, failure := range []struct {
			name     string
			response iso7816.Response
			ioError  error
			want     error
		}{
			{name: "unavailable", response: iso7816.Response{Status: 0x6a88}},
			{name: "transport", ioError: io.ErrUnexpectedEOF, want: io.ErrUnexpectedEOF},
			{name: "malformed", response: iso7816.Response{Status: 0x9000, Data: operation.malformed}, want: protocol.ErrInvalidResponse},
		} {
			t.Run(operation.name+"/"+failure.name, func(t *testing.T) {
				c := newClient(t, step{command: operation.wire, response: failure.response, err: failure.ioError})

				err := operation.read(c)

				if failure.name == "unavailable" {
					var apdu *iso7816.APDUError
					if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6a88 {
						t.Errorf("error = %v, want APDU error 6A88", err)
					}
				} else if !errors.Is(err, failure.want) {
					t.Errorf("error = %v, want %v", err, failure.want)
				}
			})
		}
	}
}
