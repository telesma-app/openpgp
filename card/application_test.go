package card

import (
	"context"
	"reflect"
	"testing"

	"github.com/telesma-app/openpgp/protocol"
)

func TestGetApplicationIdentifier(t *testing.T) {
	data := []byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0, 0}
	d := newGetterTestDevice(t, protocol.ApplicationIdentifierObject, data)
	want := protocol.ApplicationIdentifier{
		Raw: [16]byte(data), VersionMajor: 3, VersionMinor: 4, Manufacturer: 0x1234, SerialNumber: 0x56789abc,
	}

	got, err := d.GetApplicationIdentifier(t.Context())
	if err != nil || got != want {
		t.Errorf("application identifier = %+v, %v; want %+v, nil", got, err, want)
	}
}

func TestGetApplicationRelatedData(t *testing.T) {
	aid := []byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0, 0}
	data := append([]byte{0x6e, 18, 0x4f, 16}, aid...)
	d := newGetterTestDevice(t, protocol.ApplicationRelatedDataObject, data)
	want := protocol.ApplicationRelatedData{
		Raw: data,
		AID: protocol.ApplicationIdentifier{
			Raw: [16]byte(aid), VersionMajor: 3, VersionMinor: 4, Manufacturer: 0x1234, SerialNumber: 0x56789abc,
		},
	}

	got, err := d.GetApplicationRelatedData(t.Context())
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("application data = %+v, %v; want %+v, nil", got, err, want)
	}
}

func TestGetCardholderRelatedData(t *testing.T) {
	data := []byte{0x65, 14, 0x5b, 3, 'A', 'd', 'a', 0x5f, 0x2d, 2, 'e', 'n', 0x5f, 0x35, 1, '2'}
	d := newGetterTestDevice(t, protocol.CardholderRelatedDataObject, data)
	want := protocol.CardholderRelatedData{Name: []byte("Ada"), LanguagePreferences: "en", Sex: protocol.SexFemale}

	got, err := d.GetCardholderRelatedData(t.Context())
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("cardholder data = %+v, %v; want %+v, nil", got, err, want)
	}
}

func TestGetSecuritySupportTemplate(t *testing.T) {
	data := []byte{0x7a, 5, 0x93, 3, 0x12, 0x34, 0x56}
	d := newGetterTestDevice(t, protocol.SecuritySupportTemplateObject, data)
	want := protocol.SecuritySupportTemplate{DigitalSignatureCounter: 0x123456}

	got, err := d.GetSecuritySupportTemplate(t.Context())
	if err != nil || got != want {
		t.Errorf("security support template = %+v, %v; want %+v, nil", got, err, want)
	}
}

func TestApplicationGetterLifecycle(t *testing.T) {
	for _, operation := range []struct {
		name string
		data []byte
		read func(context.Context, *Device) error
	}{
		{
			name: "GetApplicationIdentifier",
			data: []byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0, 0},
			read: func(ctx context.Context, d *Device) error {
				_, err := d.GetApplicationIdentifier(ctx)
				return err
			},
		},
		{
			name: "GetApplicationRelatedData",
			data: []byte{0x4f, 16, 0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0, 0},
			read: func(ctx context.Context, d *Device) error {
				_, err := d.GetApplicationRelatedData(ctx)
				return err
			},
		},
		{
			name: "GetCardholderRelatedData",
			data: []byte{0x65, 14, 0x5b, 3, 'A', 'd', 'a', 0x5f, 0x2d, 2, 'e', 'n', 0x5f, 0x35, 1, '2'},
			read: func(ctx context.Context, d *Device) error {
				_, err := d.GetCardholderRelatedData(ctx)
				return err
			},
		},
		{
			name: "GetSecuritySupportTemplate",
			data: []byte{0x7a, 5, 0x93, 3, 0x12, 0x34, 0x56},
			read: func(ctx context.Context, d *Device) error {
				_, err := d.GetSecuritySupportTemplate(ctx)
				return err
			},
		},
	} {
		t.Run(operation.name, func(t *testing.T) {
			checkOperationLifecycle(t, operation.data, operation.read)
		})
	}
}
