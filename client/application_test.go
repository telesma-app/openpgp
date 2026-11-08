package client_test

import (
	"context"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestGetApplicationIdentifier(t *testing.T) {
	for _, test := range []struct {
		name string
		new  func(*testing.T, ...step) *client.Client
		wire []byte
	}{
		{name: "short", new: newClient, wire: []byte{0, 0xca, 0, 0x4f, 0}},
		{name: "extended", new: newExtendedClient, wire: []byte{0, 0xca, 0, 0x4f, 0, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			aid := [16]byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0, 0}
			c := test.new(t, step{command: test.wire, response: iso7816.Response{Status: 0x9000, Data: aid[:]}})
			want := protocol.ApplicationIdentifier{
				Raw: aid, VersionMajor: 3, VersionMinor: 4, Manufacturer: 0x1234, SerialNumber: 0x56789abc,
			}

			got, err := c.GetApplicationIdentifier(t.Context())
			if err != nil || got != want {
				t.Errorf("application identifier = %+v, %v; want %+v, nil", got, err, want)
			}
		})
	}
}

func TestGetApplicationRelatedData(t *testing.T) {
	for _, test := range []struct {
		name string
		new  func(*testing.T, ...step) *client.Client
		wire []byte
	}{
		{name: "short", new: newClient, wire: []byte{0, 0xca, 0, 0x6e, 0}},
		{name: "extended", new: newExtendedClient, wire: []byte{0, 0xca, 0, 0x6e, 0, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			aid := [16]byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0, 0}
			data := append([]byte{0x6e, 0x12, 0x4f, 0x10}, aid[:]...)
			c := test.new(t, step{command: test.wire, response: iso7816.Response{Status: 0x9000, Data: data}})
			want := protocol.ApplicationRelatedData{
				Raw: data,
				AID: protocol.ApplicationIdentifier{
					Raw: aid, VersionMajor: 3, VersionMinor: 4, Manufacturer: 0x1234, SerialNumber: 0x56789abc,
				},
			}

			got, err := c.GetApplicationRelatedData(t.Context())
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("application related data = %+v, %v; want %+v, nil", got, err, want)
			}
		})
	}
}

func TestGetCardholderRelatedData(t *testing.T) {
	for _, test := range []struct {
		name string
		new  func(*testing.T, ...step) *client.Client
		wire []byte
	}{
		{name: "short", new: newClient, wire: []byte{0, 0xca, 0, 0x65, 0}},
		{name: "extended", new: newExtendedClient, wire: []byte{0, 0xca, 0, 0x65, 0, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := []byte{
				0x65, 0x1b, 0x5b, 14, 'E', 'x', 'a', 'm', 'p', 'l', 'e', '<', '<', 'A', 'l', 'i', 'c', 'e',
				0x5f, 0x2d, 4, 'e', 'n', 'r', 'u', 0x5f, 0x35, 1, '2',
			}
			c := test.new(t, step{command: test.wire, response: iso7816.Response{Status: 0x9000, Data: data}})
			want := protocol.CardholderRelatedData{Name: []byte("Example<<Alice"), LanguagePreferences: "enru", Sex: protocol.SexFemale}

			got, err := c.GetCardholderRelatedData(t.Context())
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("cardholder related data = %+v, %v; want %+v, nil", got, err, want)
			}
		})
	}
}

func TestGetSecuritySupportTemplate(t *testing.T) {
	for _, test := range []struct {
		name string
		new  func(*testing.T, ...step) *client.Client
		wire []byte
	}{
		{name: "short", new: newClient, wire: []byte{0, 0xca, 0, 0x7a, 0}},
		{name: "extended", new: newExtendedClient, wire: []byte{0, 0xca, 0, 0x7a, 0, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := []byte{0x7a, 5, 0x93, 3, 0x12, 0x34, 0x56}
			c := test.new(t, step{command: test.wire, response: iso7816.Response{Status: 0x9000, Data: data}})
			want := protocol.SecuritySupportTemplate{DigitalSignatureCounter: 0x123456}

			got, err := c.GetSecuritySupportTemplate(t.Context())
			if err != nil || got != want {
				t.Errorf("security support template = %+v, %v; want %+v, nil", got, err, want)
			}
		})
	}
}

func TestApplicationReadErrors(t *testing.T) {
	for _, operation := range []struct {
		name      string
		wire      []byte
		malformed []byte
		read      func(context.Context, *client.Client) error
	}{
		{
			name: "application identifier", wire: []byte{0, 0xca, 0, 0x4f, 0}, malformed: []byte{0xd2},
			read: func(ctx context.Context, c *client.Client) error {
				_, err := c.GetApplicationIdentifier(ctx)
				return err
			},
		},
		{
			name: "application related data", wire: []byte{0, 0xca, 0, 0x6e, 0}, malformed: []byte{0x6e, 0},
			read: func(ctx context.Context, c *client.Client) error {
				_, err := c.GetApplicationRelatedData(ctx)
				return err
			},
		},
		{
			name: "cardholder related data", wire: []byte{0, 0xca, 0, 0x65, 0}, malformed: []byte{0x5f, 0x35, 1, 0xff},
			read: func(ctx context.Context, c *client.Client) error {
				_, err := c.GetCardholderRelatedData(ctx)
				return err
			},
		},
		{
			name: "security support template", wire: []byte{0, 0xca, 0, 0x7a, 0}, malformed: []byte{0x93, 2, 0, 0},
			read: func(ctx context.Context, c *client.Client) error {
				_, err := c.GetSecuritySupportTemplate(ctx)
				return err
			},
		},
	} {
		for _, failure := range []struct {
			name    string
			status  iso7816.StatusWord
			data    []byte
			ioError error
			want    error
		}{
			{name: "unavailable", status: 0x6a88},
			{name: "transport", ioError: io.ErrUnexpectedEOF, want: io.ErrUnexpectedEOF},
			{name: "malformed", status: 0x9000, data: operation.malformed, want: protocol.ErrInvalidResponse},
		} {
			t.Run(operation.name+"/"+failure.name, func(t *testing.T) {
				response := iso7816.Response{Status: failure.status, Data: failure.data}
				c := newClient(t, step{command: operation.wire, response: response, err: failure.ioError})

				err := operation.read(t.Context(), c)

				if failure.want != nil {
					if !errors.Is(err, failure.want) {
						t.Errorf("error = %v, want %v", err, failure.want)
					}
				} else {
					var apdu *iso7816.APDUError
					if !errors.As(err, &apdu) || apdu.StatusWord() != failure.status {
						t.Errorf("error = %v, want APDU error %s", err, failure.status)
					}
				}
			})
		}
	}
}
