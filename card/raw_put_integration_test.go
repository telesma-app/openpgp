package card_test

import (
	"testing"

	baseiso7816 "github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestIntegrationRawEmptyPutDataPreservesAbsentLe(t *testing.T) {
	device := newEncodingDevice(t, []client.Option{client.WithExtendedLength(), client.WithEmptyPutDataLe()}, encodingExchange{
		request:  []byte{0x00, 0xda, 0x7f, 0x21},
		response: []byte{0x90, 0x00},
	})

	response, err := device.Exchange(t.Context(), baseiso7816.Command{
		INS: byte(protocol.PutData), P1: 0x7f, P2: 0x21, Encoding: baseiso7816.EncodingShort,
	})
	if err != nil {
		t.Fatal(err)
	}

	if response.Status != baseiso7816.StatusSuccess || len(response.Data) != 0 {
		t.Errorf("Exchange = %x, %s; want empty data, 9000", response.Data, response.Status)
	}
}

func TestIntegrationEmptyPutDataOptionReachesDevice(t *testing.T) {
	for _, test := range []struct {
		name    string
		options []client.Option
		request []byte
	}{
		{"standard", []client.Option{client.WithExtendedLength()}, []byte{0, 0xda, 0x7f, 0x21}},
		{"compatibility", []client.Option{client.WithExtendedLength(), client.WithEmptyPutDataLe()}, []byte{0, 0xda, 0x7f, 0x21, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			device := newEncodingDevice(t, test.options, encodingExchange{
				request: test.request, response: []byte{0x90, 0},
			})
			if err := device.PutData(t.Context(), protocol.CardholderCertificateObject, nil, protocol.PW3, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}
