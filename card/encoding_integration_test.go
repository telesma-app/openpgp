package card_test

import (
	"bytes"
	"errors"
	"testing"

	baseiso7816 "github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestIntegrationDecipherCommandEncoding(t *testing.T) {
	// RSA-2048 input consists of the padding indicator and a 256-byte ciphertext.
	input := append([]byte{0}, bytes.Repeat([]byte{0xab}, 256)...)
	plaintext := []byte{1, 2, 3, 4}

	response := append([]byte{1, 2, 3, 4}, 0x90, 0x00)

	for _, test := range []struct {
		name      string
		options   []client.Option
		exchanges []encodingExchange
	}{
		{
			name: "default short chaining",
			exchanges: []encodingExchange{
				{
					request:  append([]byte{0x10, 0x2a, 0x80, 0x86, 0xff}, input[:255]...),
					response: []byte{0x90, 0x00},
				},
				{
					request:  []byte{0x00, 0x2a, 0x80, 0x86, 0x02, 0xab, 0xab, 0x00},
					response: response,
				},
			},
		},
		{
			name:    "extended without chaining",
			options: []client.Option{client.WithExtendedLength()},
			exchanges: []encodingExchange{{
				request:  append(append([]byte{0x00, 0x2a, 0x80, 0x86, 0x00, 0x01, 0x01}, input...), 0x00, 0x00),
				response: response,
			}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			device := newEncodingDevice(t, test.options, test.exchanges...)

			got, err := device.Decipher(t.Context(), input, nil)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got, plaintext) {
				t.Errorf("Decipher = %x, want %x", got, plaintext)
			}
		})
	}
}

func TestIntegrationExtendedLengthRejectionDoesNotRetry(t *testing.T) {
	input := append([]byte{0}, bytes.Repeat([]byte{0xab}, 256)...)
	device := newEncodingDevice(t, []client.Option{client.WithExtendedLength()},
		encodingExchange{
			request:  append(append([]byte{0x00, 0x2a, 0x80, 0x86, 0x00, 0x01, 0x01}, input...), 0x00, 0x00),
			response: []byte{0x67, 0x00},
		},
		encodingExchange{
			request:  []byte{0x00, 0xca, 0x00, 0x5e, 0x00, 0x00, 0x00},
			response: []byte{'u', 's', 'e', 'r', 0x90, 0x00},
		},
	)

	got, err := device.Decipher(t.Context(), input, nil)

	var apduError *baseiso7816.APDUError
	if !errors.As(err, &apduError) || apduError.StatusWord() != 0x6700 || got != nil {
		t.Fatalf("Decipher = %x, %v; want APDU error 6700 and no plaintext", got, err)
	}

	data, err := device.GetData(t.Context(), protocol.LoginDataObject)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, []byte("user")) {
		t.Errorf("GetData after rejection = %x, want user", data)
	}
}

func TestIntegrationExtendedLengthPreservesRawCommandEncoding(t *testing.T) {
	device := newEncodingDevice(t, []client.Option{client.WithExtendedLength()}, encodingExchange{
		request:  []byte{0x00, 0x84, 0x00, 0x00, 0x01},
		response: []byte{0xab, 0x90, 0x00},
	})

	response, err := device.Exchange(t.Context(), baseiso7816.Command{
		INS: 0x84, Le: 1, Encoding: baseiso7816.EncodingShort,
	})
	if err != nil {
		t.Fatal(err)
	}

	if response.Status != baseiso7816.StatusSuccess || !bytes.Equal(response.Data, []byte{0xab}) {
		t.Errorf("Exchange = %x, %s; want ab, 9000", response.Data, response.Status)
	}
}

func TestIntegrationChallenge256UsesExtendedEncodingAndPreservesRawShort(t *testing.T) {
	challenge := bytes.Repeat([]byte{0x5a}, 256)
	response := append(bytes.Clone(challenge), 0x90, 0x00)
	device := newEncodingDevice(t, nil,
		encodingExchange{request: []byte{0, 0x84, 0, 0, 0, 1, 0}, response: response},
		encodingExchange{request: []byte{0, 0x84, 0, 0, 0}, response: response},
	)

	got, err := device.GetChallenge(t.Context(), 256)
	if err != nil || !bytes.Equal(got, challenge) {
		t.Fatalf("GetChallenge = %x, %v; want 256 bytes", got, err)
	}

	raw, err := device.Exchange(t.Context(), baseiso7816.Command{
		INS: 0x84, Le: 256, Encoding: baseiso7816.EncodingShort,
	})
	if err != nil || raw.Status != baseiso7816.StatusSuccess || !bytes.Equal(raw.Data, challenge) {
		t.Fatalf("raw short challenge = %x, %s, %v; want 256 bytes and 9000", raw.Data, raw.Status, err)
	}
}
