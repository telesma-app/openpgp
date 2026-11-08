package card_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestCardholderCertificateWireEncoding(t *testing.T) {
	certificate := bytes.Repeat([]byte{0x5a, 0xc3, 0x00, 0xff}, 75)

	for _, test := range []struct {
		name      string
		options   []client.Option
		exchanges []encodingExchange
	}{
		{
			name: "default short chaining",
			exchanges: []encodingExchange{
				{
					request:  []byte{0x00, 0xa5, 0x02, 0x04, 0x06, 0x60, 0x04, 0x5c, 0x02, 0x7f, 0x21, 0x00},
					response: []byte{0x90, 0x00},
				},
				{
					request:  []byte{0x00, 0xca, 0x7f, 0x21, 0x00},
					response: slices.Concat(certificate[:256], []byte{0x61, 0x2c}),
				},
				{
					request:  []byte{0x00, 0xc0, 0x00, 0x00, 0x2c},
					response: slices.Concat(certificate[256:], []byte{0x90, 0x00}),
				},
				{
					request:  []byte{0x00, 0xa5, 0x01, 0x04, 0x06, 0x60, 0x04, 0x5c, 0x02, 0x7f, 0x21, 0x00},
					response: []byte{0x90, 0x00},
				},
				{
					request:  slices.Concat([]byte{0x10, 0xda, 0x7f, 0x21, 0xff}, certificate[:255]),
					response: []byte{0x90, 0x00},
				},
				{
					request:  slices.Concat([]byte{0x00, 0xda, 0x7f, 0x21, 0x2d}, certificate[255:]),
					response: []byte{0x90, 0x00},
				},
			},
		},
		{
			name:    "extended without chaining",
			options: []client.Option{client.WithExtendedLength()},
			exchanges: []encodingExchange{
				{
					request:  []byte{0x00, 0xa5, 0x02, 0x04, 0x00, 0x00, 0x06, 0x60, 0x04, 0x5c, 0x02, 0x7f, 0x21, 0x00, 0x00},
					response: []byte{0x90, 0x00},
				},
				{
					request:  []byte{0x00, 0xca, 0x7f, 0x21, 0x00, 0x00, 0x00},
					response: slices.Concat(certificate, []byte{0x90, 0x00}),
				},
				{
					request:  []byte{0x00, 0xa5, 0x01, 0x04, 0x00, 0x00, 0x06, 0x60, 0x04, 0x5c, 0x02, 0x7f, 0x21, 0x00, 0x00},
					response: []byte{0x90, 0x00},
				},
				{
					request:  slices.Concat([]byte{0x00, 0xda, 0x7f, 0x21, 0x00, 0x01, 0x2c}, certificate),
					response: []byte{0x90, 0x00},
				},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			device := newEncodingDevice(t, test.options, test.exchanges...)

			got, err := device.GetCardholderCertificate(t.Context(), protocol.DigitalSignatureTemplateTag)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got, certificate) {
				t.Errorf("GetCardholderCertificate = %x, want %x", got, certificate)
			}

			if err := device.PutCardholderCertificate(t.Context(), protocol.ConfidentialityTemplateTag, certificate, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}
