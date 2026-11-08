package protocol_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/telesma-app/openpgp/protocol"
)

func TestKeyInformation(t *testing.T) {
	got, err := protocol.ParseKeyInformation([]byte{1, 1, 2, 0, 3, 2, 0x81, 2})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(got, []protocol.KeyInformation{
		{Reference: protocol.SignatureKeyReference, Status: protocol.KeyStatusGenerated},
		{Reference: protocol.DecryptionKeyReference, Status: protocol.KeyStatusNotPresent},
		{Reference: protocol.AuthenticationKeyReference, Status: protocol.KeyStatusImported},
		{Reference: protocol.AttestationKeyReference, Status: protocol.KeyStatusImported},
	}) {
		t.Errorf("keys = %+v", got)
	}

	if _, err := protocol.ParseKeyInformation([]byte{1, 1, 0, 2, 1, 0, 3, 1, 0}); !errors.Is(err, protocol.ErrInvalidResponse) {
		t.Errorf("odd key information error = %v", err)
	}
}
