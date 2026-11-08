package card

import (
	"bytes"
	"context"
	"crypto"
	"testing"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

func TestBrainpoolCardReadAndGenerate(t *testing.T) {
	for _, fixture := range brainpoolCardFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			point := decodeHex(t, fixture.point)
			response := bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, point))

			for _, algorithm := range []struct {
				name      string
				algorithm protocol.Algorithm
				tag       protocol.ControlReferenceTemplateTag
			}{
				{name: "ECDSA", algorithm: protocol.ECDSA, tag: protocol.DigitalSignatureTemplateTag},
				{name: "ECDH", algorithm: protocol.ECDH, tag: protocol.ConfidentialityTemplateTag},
			} {
				t.Run(algorithm.name, func(t *testing.T) {
					attributes := protocol.AlgorithmAttributes{Algorithm: algorithm.algorithm, CurveOID: fixture.oid}

					for _, operation := range []struct {
						name string
						p1   byte
						call func(*Device, context.Context, protocol.ControlReferenceTemplate, protocol.AlgorithmAttributes) (crypto.PublicKey, error)
					}{
						{name: "read", p1: 0x81, call: (*Device).ReadPublicKeyWithTemplate},
						{
							name: "generate", p1: 0x80,
							call: func(d *Device, ctx context.Context, template protocol.ControlReferenceTemplate, attributes protocol.AlgorithmAttributes) (crypto.PublicKey, error) {
								return d.GenerateAsymmetricKeyPairWithTemplate(ctx, template, attributes, nil)
							},
						},
					} {
						t.Run(operation.name, func(t *testing.T) {
							calls := 0
							d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
								calls++

								if command.INS != 0x47 || command.P1 != operation.p1 || !bytes.Equal(command.Data, []byte{byte(algorithm.tag), 0}) {
									t.Fatalf("key command = %+v", command)
								}

								return success(response), nil
							}})

							t.Cleanup(func() { _ = d.Close() })

							public, err := operation.call(d, t.Context(), protocol.ControlReferenceTemplate{Tag: algorithm.tag}, attributes)
							if err != nil {
								t.Fatal(err)
							}

							checkBrainpoolCardKey(t, fixture, algorithm.algorithm, public)

							if calls != 1 {
								t.Errorf("key commands = %d, want 1", calls)
							}
						})
					}
				})
			}
		})
	}
}
