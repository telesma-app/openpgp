package client_test

import (
	"bytes"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
)

func TestPrivateKeyCommandWire(t *testing.T) {
	for _, tt := range []struct {
		name    string
		command []byte
		call    func(*client.Client) ([]byte, error)
	}{
		{name: "signature", command: []byte{0, 0x2a, 0x9e, 0x9a, 3, 1, 2, 3, 0}, call: func(c *client.Client) ([]byte, error) { return c.ComputeDigitalSignature(t.Context(), []byte{1, 2, 3}) }},
		{name: "authenticate", command: []byte{0, 0x88, 0, 0, 3, 1, 2, 3, 0}, call: func(c *client.Client) ([]byte, error) { return c.InternalAuthenticate(t.Context(), []byte{1, 2, 3}) }},
		{name: "decipher", command: []byte{0, 0x2a, 0x80, 0x86, 3, 0, 2, 3, 0}, call: func(c *client.Client) ([]byte, error) { return c.Decipher(t.Context(), []byte{0, 2, 3}) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newClient(t, step{command: tt.command, response: iso7816.Response{Status: 0x9000, Data: []byte{4, 5}}})

			got, err := tt.call(c)
			if err != nil || !bytes.Equal(got, []byte{4, 5}) {
				t.Fatalf("result = %x, error = %v", got, err)
			}
		})
	}
}
