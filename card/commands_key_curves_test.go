package card

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"testing"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

func TestCurveExtensionsReadAndGenerate(t *testing.T) {
	for _, test := range []struct {
		name      string
		algorithm protocol.Algorithm
		oid       string
		tag       protocol.ControlReferenceTemplateTag
		point     string
	}{
		{name: "Ed448", algorithm: protocol.EdDSA, oid: "2b6571", tag: protocol.DigitalSignatureTemplateTag, point: cardEd448Point},
		{name: "X448", algorithm: protocol.ECDH, oid: "2b656f", tag: protocol.ConfidentialityTemplateTag, point: cardX448Point},
		{name: "secp256k1 ECDSA", algorithm: protocol.ECDSA, oid: "2b8104000a", tag: protocol.DigitalSignatureTemplateTag, point: cardSecp256k1Point},
		{name: "secp256k1 ECDH", algorithm: protocol.ECDH, oid: "2b8104000a", tag: protocol.ConfidentialityTemplateTag, point: cardSecp256k1Point},
	} {
		t.Run(test.name, func(t *testing.T) {
			attributes := protocol.AlgorithmAttributes{Algorithm: test.algorithm, CurveOID: decodeHex(t, test.oid), ImportFormat: protocol.ImportFormatStandardWithPublicKey}
			response := bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, decodeHex(t, test.point)))

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

			checkCurveExtensionPublic(t, test.algorithm, test.oid, public, decodeHex(t, test.point))

			public, err = d.GenerateAsymmetricKeyPairWithTemplate(t.Context(), template, attributes, nil)
			if err != nil {
				t.Fatal(err)
			}

			checkCurveExtensionPublic(t, test.algorithm, test.oid, public, decodeHex(t, test.point))

			if !bytes.Equal(instructions, []byte{0x47, 0x47}) {
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
		if algorithm != protocol.ECDH || !bytes.Equal(public.CurveOID, decodeHex(t, oid)) || !bytes.Equal(public.PublicPoint, point) {
			t.Errorf("ECDH key = %+v", public)
		}
	default:
		t.Fatalf("public key type = %T", key)
	}
}
