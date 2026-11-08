package card

import (
	"bytes"
	"context"
	"crypto"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

func TestCurveExtensionsImportWithAuthentication(t *testing.T) {
	edPrivate := ed448.NewKeyFromSeed(decodeHex(t, cardEd448Seed))
	defer clear(edPrivate)

	xPrivate := protocol.X448PrivateKey(decodeHex(t, cardX448Secret))
	secpPrivate := protocol.ECPrivateKey{CurveOID: decodeHex(t, "2b8104000a"), Scalar: make([]byte, 32), PublicPoint: decodeHex(t, cardSecp256k1Point)}
	secpPrivate.Scalar[31] = 1

	for _, test := range []struct {
		name      string
		algorithm protocol.Algorithm
		oid       string
		tag       protocol.ControlReferenceTemplateTag
		key       crypto.PrivateKey
		importHex string
	}{
		{name: "Ed448", algorithm: protocol.EdDSA, oid: "2b6571", tag: protocol.DigitalSignatureTemplateTag, key: edPrivate,
			importHex: "4d7eb6007f4804923999395f4872" + cardEd448Seed + cardEd448Point},
		{name: "X448", algorithm: protocol.ECDH, oid: "2b656f", tag: protocol.ConfidentialityTemplateTag, key: xPrivate,
			importHex: "4d7cb8007f4804923899385f4870" + cardX448Secret + cardX448Point},
		{name: "secp256k1 ECDSA", algorithm: protocol.ECDSA, oid: "2b8104000a", tag: protocol.DigitalSignatureTemplateTag, key: secpPrivate,
			importHex: "4d6db6007f4804922099415f4861" + "0000000000000000000000000000000000000000000000000000000000000001" + cardSecp256k1Point},
		{name: "secp256k1 ECDH", algorithm: protocol.ECDH, oid: "2b8104000a", tag: protocol.ConfidentialityTemplateTag, key: secpPrivate,
			importHex: "4d6db8007f4804922099415f4861" + "0000000000000000000000000000000000000000000000000000000000000001" + cardSecp256k1Point},
	} {
		t.Run(test.name, func(t *testing.T) {
			attributes := protocol.AlgorithmAttributes{Algorithm: test.algorithm, CurveOID: decodeHex(t, test.oid), ImportFormat: protocol.ImportFormatStandardWithPublicKey}

			wantImport := decodeHex(t, test.importHex)
			defer clear(wantImport)

			var instructions []byte

			d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				instructions = append(instructions, command.INS)
				switch len(instructions) {
				case 1:
					if command.INS != 0x20 || command.P2 != 0x83 || !bytes.Equal(command.Data, []byte("12345678")) {
						t.Fatalf("verification command = %+v", command)
					}
				case 2:
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

			if err := d.ImportKeyWithTemplate(t.Context(), template, attributes, test.key, func(context.Context) ([]byte, error) { return []byte("12345678"), nil }); err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(instructions, []byte{0x20, 0xdb}) {
				t.Errorf("commands = %x", instructions)
			}
		})
	}
}
