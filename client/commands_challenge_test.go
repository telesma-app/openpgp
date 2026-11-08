package client_test

import (
	"errors"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

func TestGetChallengeChecksLength(t *testing.T) {
	c := newClient(t,
		step{command: []byte{0, 0x84, 0, 0, 4}, response: iso7816.Response{Status: 0x9000, Data: []byte{1, 2, 3, 4}}},
		step{command: []byte{0, 0x84, 0, 0, 4}, response: iso7816.Response{Status: 0x9000, Data: []byte{1, 2, 3}}},
	)

	data, err := c.GetChallenge(t.Context(), 4)
	if err != nil || len(data) != 4 {
		t.Fatalf("challenge = %x, error = %v", data, err)
	}

	if _, err := c.GetChallenge(t.Context(), 4); !errors.Is(err, protocol.ErrInvalidResponse) {
		t.Fatalf("short challenge error = %v", err)
	}
}
