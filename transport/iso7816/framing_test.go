package iso7816

import (
	"bytes"
	"errors"
	"testing"

	baseiso7816 "github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	openpgptransport "github.com/telesma-app/openpgp/transport"
)

func TestRSA2048DecipherFitsDefaultCommandAPDULimit(t *testing.T) {
	data := make([]byte, 257) // Padding indicator 00 followed by an RSA-2048 ciphertext.
	for i := 1; i < len(data); i++ {
		data[i] = byte(i)
	}

	raw := &fakeCard{t: t, exchanges: []exchange{
		{request: append([]byte{0x10, 0x2a, 0x80, 0x86, 0xfa}, data[:250]...), response: []byte{0x90, 0}},
		{request: append(append([]byte{0, 0x2a, 0x80, 0x86, 7}, data[250:]...), 0), response: []byte{1, 2, 0x90, 0}},
	}}
	connection := New(raw)

	t.Cleanup(func() { _ = connection.Close() })

	commands := client.NewClient(connection)

	plaintext, err := commands.Decipher(t.Context(), data)
	if err != nil || !bytes.Equal(plaintext, []byte{1, 2}) {
		t.Fatalf("RSA-2048 decipher = %x, %v; want 0102", plaintext, err)
	}

	if len(raw.exchanges) != 0 {
		t.Errorf("remaining APDUs = %d", len(raw.exchanges))
	}
}

func TestExchangeBoundsTotalCommandAPDULength(t *testing.T) {
	for _, test := range []struct {
		name        string
		encoding    baseiso7816.Encoding
		limit       int
		dataLength  int
		le          uint32
		fragments   []int
		apduLengths []int
	}{
		{name: "short exact fit", encoding: baseiso7816.EncodingShort, limit: 256, dataLength: 250, le: 256, fragments: []int{250}, apduLengths: []int{256}},
		{name: "short final Le", encoding: baseiso7816.EncodingShort, limit: 256, dataLength: 251, le: 256, fragments: []int{250, 1}, apduLengths: []int{255, 7}},
		{name: "short without Le", encoding: baseiso7816.EncodingShort, limit: 256, dataLength: 252, fragments: []int{251, 1}, apduLengths: []int{256, 6}},
		{name: "short encoding cap", encoding: baseiso7816.EncodingShort, limit: 2048, dataLength: 600, le: 256, fragments: []int{255, 255, 90}, apduLengths: []int{260, 260, 96}},
		{name: "extended default size", encoding: baseiso7816.EncodingExtended, limit: 256, dataLength: 600, le: 65536, fragments: []int{247, 247, 106}, apduLengths: []int{254, 254, 115}},
		{name: "extended configured size", encoding: baseiso7816.EncodingExtended, limit: 512, dataLength: 1024, le: 65536, fragments: []int{503, 503, 18}, apduLengths: []int{510, 510, 27}},
		{name: "extended exact fit", encoding: baseiso7816.EncodingExtended, limit: 512, dataLength: 503, le: 65536, fragments: []int{503}, apduLengths: []int{512}},
		{name: "extended final Le", encoding: baseiso7816.EncodingExtended, limit: 512, dataLength: 505, le: 65536, fragments: []int{503, 2}, apduLengths: []int{510, 11}},
		{name: "extended without Le", encoding: baseiso7816.EncodingExtended, limit: 512, dataLength: 506, fragments: []int{505, 1}, apduLengths: []int{512, 8}},
		{name: "extended small final capacity", encoding: baseiso7816.EncodingExtended, limit: 10, dataLength: 3, le: 65536, fragments: []int{1, 1, 1}, apduLengths: []int{8, 8, 10}},
		{name: "extended maximum data", encoding: baseiso7816.EncodingExtended, limit: 65544, dataLength: 65535, le: 65536, fragments: []int{65535}, apduLengths: []int{65544}},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := make([]byte, test.dataLength)
			for i := range data {
				data[i] = byte(i)
			}

			raw := &fakeCard{t: t}
			offset := 0

			for i, length := range test.fragments {
				cla := byte(0x10)
				if i == len(test.fragments)-1 {
					cla = 0
				}

				request := []byte{cla, 0xda, 0x7f, 0x21}
				if test.encoding == baseiso7816.EncodingExtended {
					request = append(request, 0, byte(length>>8), byte(length))
				} else {
					request = append(request, byte(length))
				}

				request = append(request, data[offset:offset+length]...)
				offset += length

				if i == len(test.fragments)-1 && test.le != 0 {
					if test.encoding == baseiso7816.EncodingExtended {
						request = append(request, byte(test.le>>8))
					}

					request = append(request, byte(test.le))
				}

				if len(request) != test.apduLengths[i] || len(request) > test.limit {
					t.Fatalf("expected APDU %d has %d bytes, want %d within limit %d", i, len(request), test.apduLengths[i], test.limit)
				}

				raw.exchanges = append(raw.exchanges, exchange{request: request, response: []byte{0x90, 0}})
			}

			response, err := Exchange(t.Context(), raw, baseiso7816.Command{
				INS: 0xda, P1: 0x7f, P2: 0x21, Data: data, Le: test.le, Encoding: test.encoding,
			}, WithMaxCommandAPDULength(test.limit))
			if err != nil || response.Status != 0x9000 {
				t.Fatalf("Exchange = %s, %v; want success", response.Status, err)
			}

			if len(raw.exchanges) != 0 {
				t.Errorf("remaining APDUs = %d", len(raw.exchanges))
			}
		})
	}
}

func TestCommandAPDULimitConfigurationSurvivesOpen(t *testing.T) {
	for _, selectFirst := range []bool{false, true} {
		name := "New"
		if selectFirst {
			name = "Open"
		}

		t.Run(name, func(t *testing.T) {
			data := bytes.Repeat([]byte{0xab}, 50)

			raw := &fakeCard{t: t}
			if selectFirst {
				raw.exchanges = append(raw.exchanges, exchange{request: selectAPDU, response: selectResponse})
			}

			raw.exchanges = append(raw.exchanges,
				exchange{request: append([]byte{0x10, 0xda, 0x7f, 0x21, 26}, data[:26]...), response: []byte{0x90, 0}},
				exchange{request: append(append([]byte{0, 0xda, 0x7f, 0x21, 24}, data[26:]...), 0), response: []byte{0x90, 0}},
			)

			var connection *Transport

			if selectFirst {
				var err error

				connection, err = Open(t.Context(), raw, WithMaxCommandAPDULength(32))
				if err != nil {
					t.Fatal(err)
				}
			} else {
				connection = New(raw, WithMaxCommandAPDULength(32))
			}

			t.Cleanup(func() { _ = connection.Close() })

			response, err := connection.Exchange(t.Context(), baseiso7816.Command{INS: 0xda, P1: 0x7f, P2: 0x21, Data: data, Le: 256})
			if err != nil || response.Status != 0x9000 {
				t.Fatalf("Exchange = %s, %v; want success", response.Status, err)
			}

			if len(raw.exchanges) != 0 {
				t.Errorf("remaining APDUs = %d", len(raw.exchanges))
			}
		})
	}
}

func TestTooSmallCommandAPDULimitFailsBeforeIO(t *testing.T) {
	for _, test := range []struct {
		name    string
		limit   int
		command baseiso7816.Command
	}{
		{name: "GET RESPONSE header", limit: 4, command: baseiso7816.Command{INS: 0x20}},
		{name: "short data and Le", limit: 6, command: baseiso7816.Command{INS: 0xda, Data: []byte{1}, Le: 256}},
		{name: "extended Le", limit: 6, command: baseiso7816.Command{INS: 0xca, Le: 65536, Encoding: baseiso7816.EncodingExtended}},
		{name: "extended data and Le", limit: 9, command: baseiso7816.Command{INS: 0xda, Data: []byte{1}, Le: 65536, Encoding: baseiso7816.EncodingExtended}},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := &fakeCard{t: t}
			connection := New(raw, WithMaxCommandAPDULength(test.limit))

			t.Cleanup(func() { _ = connection.Close() })

			_, err := connection.Exchange(t.Context(), test.command)

			var invalidated *openpgptransport.DeviceInvalidatedError
			if !errors.Is(err, baseiso7816.ErrInvalidFragmentSize) || errors.As(err, &invalidated) {
				t.Fatalf("Exchange = %v, want size rejection before I/O", err)
			}

			if raw.closeCalls != 0 {
				t.Error("size rejection closed the card")
			}
		})
	}
}
