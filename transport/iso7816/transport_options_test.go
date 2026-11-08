package iso7816

import (
	"bytes"
	"testing"

	baseiso7816 "github.com/telesma-app/iso7816"
)

func TestCommandAPDULimitConfigurationSurvivesOpen(t *testing.T) {
	for _, selectFirst := range []bool{false, true} {
		name := "New"
		if selectFirst {
			name = "Open"
		}

		t.Run(name, func(t *testing.T) {
			data := bytes.Repeat([]byte{0xab}, 50)

			raw := newFakeCard(t, nil)
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
