package card_test

import (
	"context"
	"crypto"
	"errors"
	"io"
	"testing"

	baseiso7816 "github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/card"
	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport"
)

func TestInvalidatedControlReferenceTemplateOperationClosesDevice(t *testing.T) {
	for _, operation := range []struct {
		name string
		call func(*card.Device, context.Context, protocol.ControlReferenceTemplate, protocol.AlgorithmAttributes) (crypto.PublicKey, error)
	}{
		{name: "read", call: (*card.Device).ReadPublicKeyWithTemplate},
		{
			name: "generate",
			call: func(d *card.Device, ctx context.Context, template protocol.ControlReferenceTemplate, attributes protocol.AlgorithmAttributes) (crypto.PublicKey, error) {
				return d.GenerateAsymmetricKeyPairWithTemplate(ctx, template, attributes, nil)
			},
		},
	} {
		t.Run(operation.name, func(t *testing.T) {
			cause := errors.New("connection lost")
			closeErr := errors.New("disconnect failed")
			peer := &invalidatedControlReferenceTemplateTransport{cause: cause, closeErr: closeErr}
			device := card.New(peer)

			t.Cleanup(func() { _ = device.Close() })

			template := protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag, KeyReference: protocol.AttestationKeyReference}
			attributes := protocol.AlgorithmAttributes{
				Algorithm: protocol.ECDSA,
				CurveOID:  []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
			}

			got, err := operation.call(device, t.Context(), template, attributes)

			var invalidated *transport.DeviceInvalidatedError
			if got != nil || !errors.As(err, &invalidated) || !errors.Is(err, cause) || !errors.Is(err, closeErr) {
				t.Fatalf("operation = %v, %v; want nil key, invalidation, I/O cause, and close cause", got, err)
			}

			if _, err := device.ReadPublicKeyWithTemplate(t.Context(), template, attributes); !errors.Is(err, io.ErrClosedPipe) {
				t.Errorf("operation after invalidation = %v, want closed pipe", err)
			}

			if err := device.Close(); !errors.Is(err, closeErr) {
				t.Errorf("Close error = %v, want disconnect failure", err)
			}

			if peer.calls != 1 || peer.closes != 1 {
				t.Errorf("exchanges = %d, closes = %d; want 1, 1", peer.calls, peer.closes)
			}
		})
	}
}

type invalidatedControlReferenceTemplateTransport struct {
	cause    error
	closeErr error
	calls    int
	closes   int
}

func (p *invalidatedControlReferenceTemplateTransport) Exchange(context.Context, baseiso7816.Command) (baseiso7816.Response, error) {
	p.calls++
	return baseiso7816.Response{}, &transport.DeviceInvalidatedError{Err: p.cause}
}

func (p *invalidatedControlReferenceTemplateTransport) Close() error {
	p.closes++
	return p.closeErr
}
