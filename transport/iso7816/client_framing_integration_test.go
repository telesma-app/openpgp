package iso7816

import (
	"bytes"
	"testing"

	"github.com/telesma-app/openpgp/client"
)

func TestIntegrationRSA2048DecipherFitsDefaultCommandAPDULimit(t *testing.T) {
	data := make([]byte, 257) // Padding indicator 00 followed by an RSA-2048 ciphertext.
	for i := 1; i < len(data); i++ {
		data[i] = byte(i)
	}

	raw := newFakeCard(t, []exchange{
		{request: append([]byte{0x10, 0x2a, 0x80, 0x86, 0xfa}, data[:250]...), response: []byte{0x90, 0}},
		{request: append(append([]byte{0, 0x2a, 0x80, 0x86, 7}, data[250:]...), 0), response: []byte{1, 2, 0x90, 0}},
	})
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
