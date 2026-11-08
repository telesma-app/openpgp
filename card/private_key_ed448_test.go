package card

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"slices"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

func TestPrivateKeyEd448RFC8032(t *testing.T) {
	for _, tamper := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "tampered"}[tamper], func(t *testing.T) {
			signature := decodeHex(t, cardEd448Signature)
			if tamper {
				signature[0] ^= 1
			}

			var instructions []byte

			d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				instructions = append(instructions, command.INS)
				switch command.INS {
				case 0xca:
					return success(keyApplication(0xc1, protocol.EdDSA, decodeHex(t, "2b6571"))), nil
				case 0x47:
					return success(bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, decodeHex(t, cardEd448Point)))), nil
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
			} else if err != nil || !bytes.Equal(got, decodeHex(t, cardEd448Signature)) {
				t.Fatalf("signature = %x, %v", got, err)
			}

			if !bytes.Equal(instructions, []byte{0xca, 0x47, 0x20, 0x2a}) {
				t.Errorf("commands = %x", instructions)
			}
		})
	}
}

func TestPrivateKeyEd448OptionsBeforeAuthentication(t *testing.T) {
	key := PrivateKey{publicKey: ed448.PublicKey(decodeHex(t, cardEd448Point))}
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
