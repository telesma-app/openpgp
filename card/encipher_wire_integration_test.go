package card_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"slices"
	"testing"

	"github.com/telesma-app/openpgp/client"
)

func TestIntegrationEncipherAES128KnownBlock(t *testing.T) {
	// FIPS 197 (2001), Appendix C.1: AES-128 key 000102030405060708090a0b0c0d0e0f.
	// OpenPGP Card AES-CBC uses a zero ICV, so its first block matches this vector.
	input := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	want := []byte{0x02, 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a}
	device := newEncodingDevice(t, nil, encodingExchange{
		request: []byte{
			0x00, 0x2a, 0x86, 0x80, 0x10,
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
		},
		response: append(slices.Clone(want), 0x90, 0x00),
	})

	got, err := device.Encipher(t.Context(), input, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("Encipher = %x, want padding indicator and ciphertext %x", got, want)
	}
}

func TestIntegrationEncipherAESMultiBlockCommandEncoding(t *testing.T) {
	key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	input := make([]byte, 320)
	for i := range input {
		input[i] = byte(i)
	}

	wantInput := slices.Clone(input)
	ciphertext := make([]byte, len(input))
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(ciphertext, input)
	want := append([]byte{0x02}, ciphertext...)

	for _, test := range []struct {
		name      string
		options   []client.Option
		exchanges []encodingExchange
	}{
		{
			name: "default chaining and GET RESPONSE",
			exchanges: []encodingExchange{
				{
					request:  append([]byte{0x10, 0x2a, 0x86, 0x80, 0xff}, input[:255]...),
					response: []byte{0x90, 0x00},
				},
				{
					request:  append(append([]byte{0x00, 0x2a, 0x86, 0x80, 0x41}, input[255:]...), 0x00),
					response: append(slices.Clone(want[:200]), 0x61, 0x79),
				},
				{
					request:  []byte{0x00, 0xc0, 0x00, 0x00, 0x79},
					response: append(slices.Clone(want[200:]), 0x90, 0x00),
				},
			},
		},
		{
			name:    "extended without chaining",
			options: []client.Option{client.WithExtendedLength()},
			exchanges: []encodingExchange{{
				request:  append(append([]byte{0x00, 0x2a, 0x86, 0x80, 0x00, 0x01, 0x40}, input...), 0x00, 0x00),
				response: append(slices.Clone(want), 0x90, 0x00),
			}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			device := newEncodingDevice(t, test.options, test.exchanges...)

			got, err := device.Encipher(t.Context(), input, nil)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got, want) {
				t.Errorf("Encipher = %x, want raw padding indicator and ciphertext %x", got, want)
			}

			if !bytes.Equal(input, wantInput) {
				t.Error("borrowed plaintext was changed")
			}
		})
	}
}
