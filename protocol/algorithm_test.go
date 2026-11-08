package protocol_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/telesma-app/openpgp/protocol"
)

func TestAlgorithmAttributes(t *testing.T) {
	for _, data := range [][]byte{nil, {1, 8, 0, 0, 32}, {1, 8, 0, 0, 32, 4}, {19}, {19, 0x2b, 0x80, 0}, {19, 0x2b, 0x81}} {
		if _, err := protocol.ParseAlgorithmAttributes(data); !errors.Is(err, protocol.ErrInvalidResponse) {
			t.Errorf("attributes %x: error = %v", data, err)
		}
	}

	unknown := []byte{0x7e, 1, 2, 3}

	got, err := protocol.ParseAlgorithmAttributes(unknown)
	if err != nil || got.Algorithm != 0x7e || !reflect.DeepEqual(got.Raw, unknown) {
		t.Errorf("unknown algorithm = %+v, %v", got, err)
	}
}

func TestCheckSupportedAlgorithms(t *testing.T) {
	for _, attributes := range []protocol.AlgorithmAttributes{
		{Algorithm: 99},
		{Algorithm: protocol.ECDSA, CurveOID: []byte{0x2b, 0x65, 0x70}},
		{Algorithm: protocol.EdDSA, CurveOID: []byte{0x2b, 0x65, 0x6e}},
		{Algorithm: protocol.ECDH, CurveOID: []byte{0x2b, 0x81, 4, 0, 9}},
	} {
		if err := attributes.CheckSupported(); !errors.Is(err, protocol.ErrUnsupportedAlgorithm) {
			t.Errorf("attributes %+v: error = %v", attributes, err)
		}
	}
}
