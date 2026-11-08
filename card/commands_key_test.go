package card

import (
	"context"
	"errors"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

func TestUnsupportedGenerationSkipsAuthentication(t *testing.T) {
	d := New(&exchangeTransport{exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
		t.Error("unsupported generation transmitted data")
		return success(nil), nil
	}})

	t.Cleanup(func() { _ = d.Close() })

	_, err := d.GenerateAsymmetricKeyPairWithTemplate(
		t.Context(),
		protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag},
		protocol.AlgorithmAttributes{Algorithm: protocol.Algorithm(99)},
		func(context.Context) ([]byte, error) {
			t.Error("unsupported generation called authentication source")
			return []byte("encoded PW3"), nil
		},
	)
	if !errors.Is(err, protocol.ErrUnsupportedAlgorithm) {
		t.Errorf("error = %v, want protocol.ErrUnsupportedAlgorithm", err)
	}
}
