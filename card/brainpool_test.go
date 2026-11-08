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

type brainpoolCardFixture struct {
	name  string
	oid   []byte
	point string
}

// RFC 5639, Sections 3.4, 3.6 and 3.7: these fixed public points are the
// generators, so each is the public key for the test-only private scalar 1.
var brainpoolCardFixtures = []brainpoolCardFixture{
	{
		name: "brainpoolP256r1", oid: []byte{0x2b, 0x24, 3, 3, 2, 8, 1, 1, 7},
		point: "04" +
			"8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262" +
			"547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
	},
	{
		name: "brainpoolP384r1", oid: []byte{0x2b, 0x24, 3, 3, 2, 8, 1, 1, 0x0b},
		point: "04" +
			"1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e" +
			"8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315",
	},
	{
		name: "brainpoolP512r1", oid: []byte{0x2b, 0x24, 3, 3, 2, 8, 1, 1, 0x0d},
		point: "04" +
			"81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822" +
			"7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
	},
}

func checkBrainpoolCardKey(t testing.TB, fixture brainpoolCardFixture, algorithm protocol.Algorithm, public crypto.PublicKey) {
	t.Helper()

	point := unhex(t, fixture.point)

	if algorithm == protocol.ECDSA {
		key, ok := public.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("public key type = %T, want ECDSA", public)
		}

		width := (len(point) - 1) / 2
		//nolint:staticcheck // Go's ECDSA key encoding methods do not support Brainpool curves.
		if key.Curve.Params().Name != fixture.name || !bytes.Equal(key.X.Bytes(), point[1:1+width]) || !bytes.Equal(key.Y.Bytes(), point[1+width:]) {
			t.Errorf("ECDSA key = %+v, want %s generator", key, fixture.name)
		}

		return
	}

	key, ok := public.(protocol.ECDHPublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want Brainpool ECDH", public)
	}

	if !bytes.Equal(key.CurveOID, fixture.oid) || !bytes.Equal(key.PublicPoint, point) {
		t.Errorf("ECDH key = %+v, want OID %x point %x", key, fixture.oid, point)
	}
}

func brainpoolCardApplication(object byte, algorithm protocol.Algorithm, oid []byte) []byte {
	attributes := append([]byte{byte(algorithm)}, oid...)
	data := bertlv.Append(nil, 0x4f, []byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 1, 0, 0, 0, 1, 0, 0})
	data = bertlv.Append(data, 0x73, bertlv.Append(nil, uint32(object), attributes))

	return bertlv.Append(nil, 0x6e, data)
}

func TestBrainpoolCardReadAndGenerate(t *testing.T) {
	for _, fixture := range brainpoolCardFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			point := unhex(t, fixture.point)
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
					point := unhex(t, fixture.point)
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

							return success(brainpoolCardApplication(0xc1, protocol.ECDSA, fixture.oid)), nil
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
			point := unhex(t, fixture.point)
			response := bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, point))
			calls := 0
			d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				calls++

				switch command.INS {
				case byte(protocol.GetData):
					return success(brainpoolCardApplication(0xc2, protocol.ECDH, fixture.oid)), nil
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
