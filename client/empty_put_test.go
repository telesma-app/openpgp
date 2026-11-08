package client_test

import (
	"bytes"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestEmptyPutDataEncoding(t *testing.T) {
	for _, tt := range []struct {
		name    string
		options []client.Option
		data    []byte
		command []byte
	}{
		{
			name:    "short nil",
			command: []byte{0, 0xda, 0x7f, 0x21},
		},
		{
			name:    "short empty",
			data:    []byte{},
			command: []byte{0, 0xda, 0x7f, 0x21},
		},
		{
			name:    "extended nil",
			options: []client.Option{client.WithExtendedLength()},
			command: []byte{0, 0xda, 0x7f, 0x21},
		},
		{
			name:    "extended empty",
			options: []client.Option{client.WithExtendedLength()},
			data:    []byte{},
			command: []byte{0, 0xda, 0x7f, 0x21},
		},
		{
			name:    "compatibility short nil",
			options: []client.Option{client.WithEmptyPutDataLe()},
			command: []byte{0, 0xda, 0x7f, 0x21, 0},
		},
		{
			name:    "compatibility short empty",
			options: []client.Option{client.WithEmptyPutDataLe()},
			data:    []byte{},
			command: []byte{0, 0xda, 0x7f, 0x21, 0},
		},
		{
			name:    "compatibility extended nil",
			options: []client.Option{client.WithExtendedLength(), client.WithEmptyPutDataLe()},
			command: []byte{0, 0xda, 0x7f, 0x21, 0},
		},
		{
			name:    "compatibility extended empty",
			options: []client.Option{client.WithEmptyPutDataLe(), client.WithExtendedLength()},
			data:    []byte{},
			command: []byte{0, 0xda, 0x7f, 0x21, 0},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := &peer{t: t, steps: []step{{command: tt.command, response: iso7816.Response{Status: 0x9000}}}}
			t.Cleanup(func() {
				if p.index != len(p.steps) {
					t.Errorf("exchanges = %d, want %d", p.index, len(p.steps))
				}
			})

			c := client.NewClient(p, tt.options...)

			if err := c.PutData(t.Context(), protocol.CardholderCertificateObject, tt.data); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPutDataNonemptyOmitsLe(t *testing.T) {
	for _, tt := range []struct {
		name    string
		options []client.Option
		command []byte
	}{
		{
			name:    "short",
			command: []byte{0, 0xda, 0x7f, 0x21, 3, 0x7f, 0x21, 0},
		},
		{
			name:    "extended",
			options: []client.Option{client.WithExtendedLength()},
			command: []byte{0, 0xda, 0x7f, 0x21, 0, 0, 3, 0x7f, 0x21, 0},
		},
		{
			name:    "compatibility short",
			options: []client.Option{client.WithEmptyPutDataLe()},
			command: []byte{0, 0xda, 0x7f, 0x21, 3, 0x7f, 0x21, 0},
		},
		{
			name:    "compatibility extended",
			options: []client.Option{client.WithExtendedLength(), client.WithEmptyPutDataLe()},
			command: []byte{0, 0xda, 0x7f, 0x21, 0, 0, 3, 0x7f, 0x21, 0},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := &peer{t: t, steps: []step{{command: tt.command, response: iso7816.Response{Status: 0x9000}}}}
			t.Cleanup(func() {
				if p.index != len(p.steps) {
					t.Errorf("exchanges = %d, want %d", p.index, len(p.steps))
				}
			})

			c := client.NewClient(p, tt.options...)
			data := []byte{0x7f, 0x21, 0}

			if err := c.PutData(t.Context(), protocol.CardholderCertificateObject, data); err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(data, []byte{0x7f, 0x21, 0}) {
				t.Errorf("borrowed data changed: %x", data)
			}
		})
	}
}
