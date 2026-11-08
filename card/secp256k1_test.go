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

func TestPrivateKeySecp256k1FixedSignature(t *testing.T) {
	// SEC 1, Section 4.1.3: d=1, k=1 and a zero digest give r=s=Gx.
	// Gx is the secp256k1 generator coordinate in SEC 2, Section 2.4.1.
	const coordinate = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

	signature := unhex(t, coordinate+coordinate)

	var instructions []byte

	d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
		instructions = append(instructions, command.INS)
		switch command.INS {
		case 0xca:
			return success(brainpoolCardApplication(0xc1, protocol.ECDSA, unhex(t, "2b8104000a"))), nil
		case 0x47:
			return success(bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, unhex(t, cardSecp256k1Point)))), nil
		case 0x2a:
			if command.P1 != 0x9e || command.P2 != 0x9a || !bytes.Equal(command.Data, make([]byte, 32)) {
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

	got, err := key.Sign(t.Context(), make([]byte, 32), crypto.SHA256, nil)
	if err != nil {
		t.Fatal(err)
	}

	want := unhex(t, "30440220"+coordinate+"0220"+coordinate)
	if !bytes.Equal(got, want) {
		t.Errorf("signature = %x, want DER %x", got, want)
	}

	if !bytes.Equal(instructions, []byte{0xca, 0x47, 0x2a}) {
		t.Errorf("commands = %x", instructions)
	}
}
