package card_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestCardholderCertificatesWireEncoding(t *testing.T) {
	authentication := []byte{0x30, 0x01, 0xa0}
	decryption := bytes.Repeat([]byte{0x44, 0xff, 0x00, 0xb1}, 75)
	signature := []byte{0x53, 0xff, 0x00, 0xa2}

	for _, test := range []struct {
		name      string
		options   []client.Option
		exchanges []encodingExchange
	}{
		{
			name: "default short responses",
			exchanges: []encodingExchange{
				{
					request:  []byte{0x00, 0xa5, 0x02, 0x04, 0x06, 0x60, 0x04, 0x5c, 0x02, 0x7f, 0x21, 0x00},
					response: []byte{0x90, 0x00},
				},
				{
					request:  []byte{0x00, 0xca, 0x7f, 0x21, 0x00},
					response: slices.Concat(signature, []byte{0x90, 0x00}),
				},
				{
					request:  []byte{0x00, 0xa5, 0x00, 0x04, 0x06, 0x60, 0x04, 0x5c, 0x02, 0x7f, 0x21, 0x00},
					response: []byte{0x90, 0x00},
				},
				{
					request:  []byte{0x00, 0xca, 0x7f, 0x21, 0x00},
					response: slices.Concat(authentication, []byte{0x90, 0x00}),
				},
				{
					request:  []byte{0x00, 0xcc, 0x7f, 0x21, 0x00},
					response: slices.Concat(decryption[:256], []byte{0x61, 0x2c}),
				},
				{
					request:  []byte{0x00, 0xc0, 0x00, 0x00, 0x2c},
					response: slices.Concat(decryption[256:], []byte{0x90, 0x00}),
				},
				{
					request:  []byte{0x00, 0xcc, 0x7f, 0x21, 0x00},
					response: slices.Concat(signature, []byte{0x90, 0x00}),
				},
			},
		},
		{
			name:    "extended responses",
			options: []client.Option{client.WithExtendedLength()},
			exchanges: []encodingExchange{
				{
					request:  []byte{0x00, 0xa5, 0x02, 0x04, 0x00, 0x00, 0x06, 0x60, 0x04, 0x5c, 0x02, 0x7f, 0x21, 0x00, 0x00},
					response: []byte{0x90, 0x00},
				},
				{
					request:  []byte{0x00, 0xca, 0x7f, 0x21, 0x00, 0x00, 0x00},
					response: slices.Concat(signature, []byte{0x90, 0x00}),
				},
				{
					request:  []byte{0x00, 0xa5, 0x00, 0x04, 0x00, 0x00, 0x06, 0x60, 0x04, 0x5c, 0x02, 0x7f, 0x21, 0x00, 0x00},
					response: []byte{0x90, 0x00},
				},
				{
					request:  []byte{0x00, 0xca, 0x7f, 0x21, 0x00, 0x00, 0x00},
					response: slices.Concat(authentication, []byte{0x90, 0x00}),
				},
				{
					request:  []byte{0x00, 0xcc, 0x7f, 0x21, 0x00, 0x00, 0x00},
					response: slices.Concat(decryption, []byte{0x90, 0x00}),
				},
				{
					request:  []byte{0x00, 0xcc, 0x7f, 0x21, 0x00, 0x00, 0x00},
					response: slices.Concat(signature, []byte{0x90, 0x00}),
				},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			device := newEncodingDevice(t, test.options, test.exchanges...)

			previous, err := device.GetCardholderCertificate(t.Context(), protocol.DigitalSignatureTemplateTag)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(previous, signature) {
				t.Errorf("previous SIG certificate = %x, want %x", previous, signature)
			}

			got, err := device.GetCardholderCertificates(t.Context())
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got.Authentication, authentication) {
				t.Errorf("AUT certificate = %x, want %x", got.Authentication, authentication)
			}

			if !bytes.Equal(got.Decryption, decryption) {
				t.Errorf("DEC certificate = %x, want %x", got.Decryption, decryption)
			}

			if !bytes.Equal(got.Signature, signature) {
				t.Errorf("SIG certificate = %x, want %x", got.Signature, signature)
			}
		})
	}
}
