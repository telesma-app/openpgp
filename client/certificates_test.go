package client_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestGetCardholderCertificatesWire(t *testing.T) {
	for _, tt := range []struct {
		name      string
		extended  bool
		selectSIG []byte
		selectAUT []byte
		get       []byte
		next      []byte
		want      protocol.CardholderCertificates
	}{
		{
			name:      "default",
			selectSIG: []byte{0, 0xa5, 2, 4, 6, 0x60, 4, 0x5c, 2, 0x7f, 0x21, 0},
			selectAUT: []byte{0, 0xa5, 0, 4, 6, 0x60, 4, 0x5c, 2, 0x7f, 0x21, 0},
			get:       []byte{0, 0xca, 0x7f, 0x21, 0},
			next:      []byte{0, 0xcc, 0x7f, 0x21, 0},
			want: protocol.CardholderCertificates{
				Authentication: []byte{0xa1, 1},
				Decryption:     []byte{0xd2, 2},
				Signature:      []byte{0x53, 3},
			},
		},
		{
			name:      "extended with empty middle certificate",
			extended:  true,
			selectSIG: []byte{0, 0xa5, 2, 4, 0, 0, 6, 0x60, 4, 0x5c, 2, 0x7f, 0x21, 0, 0},
			selectAUT: []byte{0, 0xa5, 0, 4, 0, 0, 6, 0x60, 4, 0x5c, 2, 0x7f, 0x21, 0, 0},
			get:       []byte{0, 0xca, 0x7f, 0x21, 0, 0, 0},
			next:      []byte{0, 0xcc, 0x7f, 0x21, 0, 0, 0},
			want: protocol.CardholderCertificates{
				Authentication: []byte{0xa1, 1},
				Signature:      []byte{0x53, 3},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			steps := []step{
				{command: tt.selectSIG, response: iso7816.Response{Status: 0x9000}},
				{command: tt.get, response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 0}}},
				{command: tt.selectAUT, response: iso7816.Response{Status: 0x9000}},
				{command: tt.get, response: iso7816.Response{Status: 0x9000, Data: tt.want.Authentication}},
				{command: tt.next, response: iso7816.Response{Status: 0x9000, Data: tt.want.Decryption}},
				{command: tt.next, response: iso7816.Response{Status: 0x9000, Data: tt.want.Signature}},
			}

			var c *client.Client
			if tt.extended {
				c = newExtendedClient(t, steps...)
			} else {
				c = newClient(t, steps...)
			}

			if _, err := c.GetCardholderCertificate(t.Context(), protocol.DigitalSignatureTemplateTag); err != nil {
				t.Fatal(err)
			}

			got, err := c.GetCardholderCertificates(t.Context())
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got.Authentication, tt.want.Authentication) ||
				!bytes.Equal(got.Decryption, tt.want.Decryption) ||
				!bytes.Equal(got.Signature, tt.want.Signature) {
				t.Errorf("certificates = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestGetCardholderCertificatesFailureDiscardsPartialResult(t *testing.T) {
	for _, tt := range []struct {
		name  string
		phase int
	}{
		{name: "select", phase: 0},
		{name: "authentication", phase: 1},
		{name: "decryption", phase: 2},
		{name: "signature", phase: 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			steps := []step{
				{command: []byte{0, 0xa5, 0, 4, 6, 0x60, 4, 0x5c, 2, 0x7f, 0x21, 0}, response: iso7816.Response{Status: 0x9000}},
				{command: []byte{0, 0xca, 0x7f, 0x21, 0}, response: iso7816.Response{Status: 0x9000, Data: []byte{0xa1}}},
				{command: []byte{0, 0xcc, 0x7f, 0x21, 0}, response: iso7816.Response{Status: 0x9000, Data: []byte{0xd2}}},
				{command: []byte{0, 0xcc, 0x7f, 0x21, 0}, response: iso7816.Response{Status: 0x9000, Data: []byte{0x53}}},
			}
			steps = steps[:tt.phase+1]
			steps[tt.phase].response = iso7816.Response{Status: 0x6a88}
			c := newClient(t, steps...)

			got, err := c.GetCardholderCertificates(t.Context())

			var apduError *iso7816.APDUError
			if !errors.As(err, &apduError) || apduError.StatusWord() != 0x6a88 {
				t.Fatalf("error = %v, want APDU error 6a88", err)
			}

			if got.Authentication != nil || got.Decryption != nil || got.Signature != nil {
				t.Errorf("partial result = %+v, want zero value", got)
			}
		})
	}
}
