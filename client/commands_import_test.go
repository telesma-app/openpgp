package client_test

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestImportKeyDataBorrowsPreparedPayload(t *testing.T) {
	_, _, material := keyImportP256Fixture(t)
	template := protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag, KeyReference: protocol.KeyReference(0x82)}

	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "success"},
		{name: "transport failure", err: io.ErrUnexpectedEOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := slices.Concat([]byte{
				0x4d, 0x70, 0xb6, 3, 0x84, 1, 0x82,
				0x7f, 0x48, 4, 0x92, 0x20, 0x99, 0x41, 0x5f, 0x48, 0x61,
			}, material)
			before := slices.Clone(data)
			want := slices.Concat([]byte{0, 0xdb, 0x3f, 0xff, 0x72}, data)

			t.Cleanup(func() {
				clear(data)
				clear(before)
				clear(want)
			})
			p := &keyImportPeer{t: t, want: want, response: iso7816.Response{Status: 0x9000}, err: test.err}
			c := client.NewClient(p)

			err := c.ImportKeyData(t.Context(), template, data)

			if !errors.Is(err, test.err) {
				t.Errorf("error = %v, want %v", err, test.err)
			}

			if p.calls != 1 {
				t.Errorf("import exchanges = %d, want one", p.calls)
			}

			if !bytes.Equal(data, before) || !bytes.Equal(p.payload, before) {
				t.Error("prepared import modified or cleared the borrowed payload")
			}
		})
	}
}
