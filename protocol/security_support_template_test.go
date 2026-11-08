package protocol_test

import (
	"errors"
	"testing"

	"github.com/telesma-app/openpgp/protocol"
)

func TestSecuritySupportTemplate(t *testing.T) {
	got, err := protocol.ParseSecuritySupportTemplate([]byte{0x7a, 5, 0x93, 3, 0x12, 0x34, 0x56})
	if err != nil || got.DigitalSignatureCounter != 0x123456 {
		t.Errorf("counter = %+v, %v", got, err)
	}

	if _, err := protocol.ParseSecuritySupportTemplate([]byte{0x93, 2, 0, 0}); !errors.Is(err, protocol.ErrInvalidResponse) {
		t.Errorf("short counter error = %v", err)
	}
}
