package card

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"errors"
	"slices"
	"testing"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

// RFC 8032, Section 7.4, Ed448's one-octet test (message 03), and
// RFC 7748, Section 6.2, Alice's X448 key pair.
const (
	cardEd448Seed      = "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e"
	cardEd448Point     = "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480"
	cardEd448Signature = "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00"
	cardX448Secret     = "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"
	cardX448Point      = "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
	cardSecp256k1Point = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)

func TestCurveExtensionsReadGenerateImport(t *testing.T) {
	edPrivate := ed448.NewKeyFromSeed(unhex(t, cardEd448Seed))
	defer clear(edPrivate)

	xPrivate := protocol.X448PrivateKey(unhex(t, cardX448Secret))
	secpPrivate := protocol.ECPrivateKey{CurveOID: unhex(t, "2b8104000a"), Scalar: make([]byte, 32), PublicPoint: unhex(t, cardSecp256k1Point)}
	secpPrivate.Scalar[31] = 1

	for _, test := range []struct {
		name      string
		algorithm protocol.Algorithm
		oid       string
		tag       protocol.ControlReferenceTemplateTag
		key       crypto.PrivateKey
		point     string
		importHex string
	}{
		{name: "Ed448", algorithm: protocol.EdDSA, oid: "2b6571", tag: protocol.DigitalSignatureTemplateTag, key: edPrivate, point: cardEd448Point,
			importHex: "4d7eb6007f4804923999395f4872" + cardEd448Seed + cardEd448Point},
		{name: "X448", algorithm: protocol.ECDH, oid: "2b656f", tag: protocol.ConfidentialityTemplateTag, key: xPrivate, point: cardX448Point,
			importHex: "4d7cb8007f4804923899385f4870" + cardX448Secret + cardX448Point},
		{name: "secp256k1 ECDSA", algorithm: protocol.ECDSA, oid: "2b8104000a", tag: protocol.DigitalSignatureTemplateTag, key: secpPrivate, point: cardSecp256k1Point,
			importHex: "4d6db6007f4804922099415f4861" + "0000000000000000000000000000000000000000000000000000000000000001" + cardSecp256k1Point},
		{name: "secp256k1 ECDH", algorithm: protocol.ECDH, oid: "2b8104000a", tag: protocol.ConfidentialityTemplateTag, key: secpPrivate, point: cardSecp256k1Point,
			importHex: "4d6db8007f4804922099415f4861" + "0000000000000000000000000000000000000000000000000000000000000001" + cardSecp256k1Point},
	} {
		t.Run(test.name, func(t *testing.T) {
			attributes := protocol.AlgorithmAttributes{Algorithm: test.algorithm, CurveOID: unhex(t, test.oid), ImportFormat: protocol.ImportFormatStandardWithPublicKey}
			response := bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, unhex(t, test.point)))

			wantImport := unhex(t, test.importHex)
			defer clear(wantImport)

			var instructions []byte

			d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				instructions = append(instructions, command.INS)
				switch len(instructions) {
				case 1, 2:
					wantP1 := byte(0x81)
					if len(instructions) == 2 {
						wantP1 = 0x80
					}

					if command.INS != 0x47 || command.P1 != wantP1 || !bytes.Equal(command.Data, []byte{byte(test.tag), 0}) {
						t.Fatalf("key command = %+v", command)
					}

					return success(response), nil
				case 3:
					if command.INS != 0x20 || command.P2 != 0x83 || !bytes.Equal(command.Data, []byte("12345678")) {
						t.Fatalf("verification command = %+v", command)
					}
				case 4:
					if command.INS != 0xdb || command.P1 != 0x3f || command.P2 != 0xff || command.Le != 0 || !bytes.Equal(command.Data, wantImport) {
						t.Fatalf("import command = %+v", command)
					}
				default:
					t.Fatalf("unexpected command = %+v", command)
				}

				return success(nil), nil
			}})

			t.Cleanup(func() { _ = d.Close() })

			template := protocol.ControlReferenceTemplate{Tag: test.tag}

			public, err := d.ReadPublicKeyWithTemplate(t.Context(), template, attributes)
			if err != nil {
				t.Fatal(err)
			}

			checkCurveExtensionPublic(t, test.algorithm, test.oid, public, unhex(t, test.point))

			public, err = d.GenerateAsymmetricKeyPairWithTemplate(t.Context(), template, attributes, nil)
			if err != nil {
				t.Fatal(err)
			}

			checkCurveExtensionPublic(t, test.algorithm, test.oid, public, unhex(t, test.point))

			if err := d.ImportKeyWithTemplate(t.Context(), template, attributes, test.key, func(context.Context) ([]byte, error) { return []byte("12345678"), nil }); err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(instructions, []byte{0x47, 0x47, 0x20, 0xdb}) {
				t.Errorf("commands = %x", instructions)
			}
		})
	}
}

func checkCurveExtensionPublic(t testing.TB, algorithm protocol.Algorithm, oid string, key crypto.PublicKey, point []byte) {
	t.Helper()

	switch public := key.(type) {
	case ed448.PublicKey:
		if algorithm != protocol.EdDSA || !bytes.Equal(public, point) {
			t.Errorf("Ed448 key = %x", public)
		}
	case x448.Key:
		if algorithm != protocol.ECDH || !bytes.Equal(public[:], point) {
			t.Errorf("X448 key = %x", public)
		}
	case *ecdsa.PublicKey:
		//nolint:staticcheck // secp256k1 has no standard-library encoding helpers.
		if algorithm != protocol.ECDSA || !bytes.Equal(public.X.Bytes(), point[1:33]) || !bytes.Equal(public.Y.Bytes(), point[33:]) {
			t.Errorf("secp256k1 key = %+v", public)
		}
	case protocol.ECDHPublicKey:
		if algorithm != protocol.ECDH || !bytes.Equal(public.CurveOID, unhex(t, oid)) || !bytes.Equal(public.PublicPoint, point) {
			t.Errorf("ECDH key = %+v", public)
		}
	default:
		t.Fatalf("public key type = %T", key)
	}
}

func TestPrivateKeyEd448RFC8032(t *testing.T) {
	for _, tamper := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "tampered"}[tamper], func(t *testing.T) {
			signature := unhex(t, cardEd448Signature)
			if tamper {
				signature[0] ^= 1
			}

			var instructions []byte

			d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				instructions = append(instructions, command.INS)
				switch command.INS {
				case 0xca:
					return success(brainpoolCardApplication(0xc1, protocol.EdDSA, unhex(t, "2b6571"))), nil
				case 0x47:
					return success(bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, unhex(t, cardEd448Point)))), nil
				case 0x20:
					if command.P2 != 0x81 || !bytes.Equal(command.Data, []byte("123456")) {
						t.Fatalf("VERIFY = %+v", command)
					}

					return success(nil), nil
				case 0x2a:
					if command.P1 != 0x9e || command.P2 != 0x9a || !bytes.Equal(command.Data, []byte{3}) {
						t.Fatalf("PSO:CDS = %+v", command)
					}

					return success(signature), nil
				default:
					t.Fatalf("unexpected command = %+v", command)
					return iso7816.Response{}, nil
				}
			}})

			t.Cleanup(func() { _ = d.Close() })

			key, err := d.PrivateKey(t.Context(), protocol.DigitalSignatureTemplateTag)
			if err != nil {
				t.Fatal(err)
			}

			got, err := key.Signer(t.Context(), func(context.Context) ([]byte, error) { return []byte("123456"), nil }).Sign(nil, []byte{3}, ed448.SignerOptions{})
			if tamper {
				if got != nil || !errors.Is(err, protocol.ErrInvalidResponse) {
					t.Fatalf("tampered signature = %x, %v", got, err)
				}
			} else if err != nil || !bytes.Equal(got, unhex(t, cardEd448Signature)) {
				t.Fatalf("signature = %x, %v", got, err)
			}

			if !bytes.Equal(instructions, []byte{0xca, 0x47, 0x20, 0x2a}) {
				t.Errorf("commands = %x", instructions)
			}
		})
	}
}

func TestPrivateKeyEd448OptionsBeforeAuthentication(t *testing.T) {
	key := PrivateKey{publicKey: ed448.PublicKey(unhex(t, cardEd448Point))}
	for _, opts := range []crypto.SignerOpts{crypto.SHA512, ed448.SignerOptions{Scheme: ed448.ED448Ph}, &ed448.SignerOptions{Context: "ctx"}} {
		got, err := key.Sign(t.Context(), []byte{3}, opts, func(context.Context) ([]byte, error) {
			t.Fatal("authentication called for unsupported signature options")
			return nil, nil
		})
		if err == nil || got != nil {
			t.Errorf("options %+v: signature = %x, %v", opts, got, err)
		}
	}

	for _, opts := range []crypto.SignerOpts{crypto.Hash(0), ed448.SignerOptions{}, &ed448.SignerOptions{}} {
		got, err := key.prepare([]byte{3}, opts)
		if err != nil || !slices.Equal(got, []byte{3}) {
			t.Errorf("options %+v: prepared = %x, %v", opts, got, err)
		}
	}
}
