package card

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

func TestBrainpoolSigningBinding(t *testing.T) {
	for _, fixture := range brainpoolCardFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			for _, invalid := range []bool{false, true} {
				name := "valid signature"
				if invalid {
					name = "invalid signature"
				}

				t.Run(name, func(t *testing.T) {
					digest := sha256.Sum256([]byte("OpenPGP Brainpool card signing"))
					point := decodeHex(t, fixture.point)
					response := bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, point))

					var rawSignature []byte

					calls := 0
					d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
						calls++

						switch command.INS {
						case byte(protocol.GetData):
							if command.P2 != 0x6e {
								t.Fatalf("metadata command = %+v", command)
							}

							return success(keyApplication(0xc1, protocol.ECDSA, fixture.oid)), nil
						case byte(protocol.GenerateAsymmetricKeyPair):
							if command.P1 != 0x81 || !bytes.Equal(command.Data, []byte{0xb6, 0}) {
								t.Fatalf("public-key command = %+v", command)
							}

							return success(response), nil
						case byte(protocol.PerformSecurityOperation):
							if command.P1 != 0x9e || command.P2 != 0x9a || !bytes.Equal(command.Data, digest[:]) {
								t.Fatalf("ECDSA signature input = %+v", command)
							}

							return success(rawSignature), nil
						default:
							t.Fatalf("unexpected instruction %02x", command.INS)
							return iso7816.Response{}, nil
						}
					}})

					t.Cleanup(func() { _ = d.Close() })

					binding, err := d.PrivateKey(t.Context(), protocol.DigitalSignatureTemplateTag)
					if err != nil {
						t.Fatal(err)
					}

					checkBrainpoolCardKey(t, fixture, protocol.ECDSA, binding.Public())
					public := binding.Public().(*ecdsa.PublicKey)
					//nolint:staticcheck // Brainpool fixtures require raw fields; Go's encoding helpers support only NIST curves.
					software := &ecdsa.PrivateKey{PublicKey: *public, D: big.NewInt(1)}

					r, s, err := ecdsa.Sign(rand.Reader, software, digest[:])
					if err != nil {
						t.Fatal(err)
					}

					width := (public.Params().N.BitLen() + 7) / 8
					rawSignature = make([]byte, 2*width)
					r.FillBytes(rawSignature[:width])
					s.FillBytes(rawSignature[width:])

					if invalid {
						clear(rawSignature[:width])
					}

					signature, err := binding.Sign(t.Context(), digest[:], crypto.SHA256, nil)
					if invalid {
						if !errors.Is(err, protocol.ErrInvalidResponse) || signature != nil {
							t.Fatalf("invalid signature = %x, %v", signature, err)
						}
					} else if err != nil || !ecdsa.VerifyASN1(public, digest[:], signature) {
						t.Fatalf("signature = %x, %v; want verified ASN.1 ECDSA", signature, err)
					}

					if calls != 3 {
						t.Errorf("binding/signing commands = %d, want metadata, public key and signature", calls)
					}
				})
			}
		})
	}
}

func TestBrainpoolECDHCannotBindSigningKey(t *testing.T) {
	for _, fixture := range brainpoolCardFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			point := decodeHex(t, fixture.point)
			response := bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, point))
			calls := 0
			d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				calls++

				switch command.INS {
				case byte(protocol.GetData):
					return success(keyApplication(0xc2, protocol.ECDH, fixture.oid)), nil
				case byte(protocol.GenerateAsymmetricKeyPair):
					if command.P1 != 0x81 || !bytes.Equal(command.Data, []byte{0xb8, 0}) {
						t.Fatalf("public-key command = %+v", command)
					}

					return success(response), nil
				default:
					t.Fatalf("unexpected instruction %02x", command.INS)
					return iso7816.Response{}, nil
				}
			}})

			t.Cleanup(func() { _ = d.Close() })

			binding, err := d.PrivateKey(t.Context(), protocol.ConfidentialityTemplateTag)

			if !errors.Is(err, protocol.ErrUnsupportedAlgorithm) || binding != nil {
				t.Fatalf("ECDH signing binding = %v, %v", binding, err)
			}

			if calls != 2 {
				t.Errorf("commands = %d, want only metadata and public key reads", calls)
			}
		})
	}
}
