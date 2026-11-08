package card

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/big"
	"slices"
	"testing"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

func TestPrivateKeyRSASigner(t *testing.T) {
	message := []byte("OpenPGP Card signing")
	sha256Digest := sha256.Sum256(message)
	sha384Digest := sha512.Sum384(message)
	sha512Digest := sha512.Sum512(message)

	// DigestInfo encodings from OpenPGP Card 3.4.1, Section 7.2.10.2.
	for _, test := range []struct {
		name   string
		hash   crypto.Hash
		digest []byte
		prefix string
	}{
		{name: "SHA256", hash: crypto.SHA256, digest: sha256Digest[:], prefix: "3031300d060960864801650304020105000420"},
		{name: "SHA384", hash: crypto.SHA384, digest: sha384Digest[:], prefix: "3041300d060960864801650304020205000430"},
		{name: "SHA512", hash: crypto.SHA512, digest: sha512Digest[:], prefix: "3051300d060960864801650304020305000440"},
	} {
		t.Run(test.name, func(t *testing.T) {
			software, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}

			digest := test.digest
			wantInput := append(decodeHex(t, test.prefix), digest...)
			password := []byte("secret PW1")

			var commands []iso7816.Command

			d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				command.Data = slices.Clone(command.Data)

				commands = append(commands, command)
				switch command.INS {
				case byte(protocol.GetData):
					if command.P2 != 0x6e {
						t.Errorf("algorithm object = %02x, want 6e", command.P2)
					}

					value := bertlv.Append(nil, 0xc1, []byte{1, 8, 0, 0, 32, 0})
					value = bertlv.Append(nil, 0x73, value)
					value = append(bertlv.Append(nil, 0x4f, decodeHex(t, "d2760001240103040006000000010000")), value...)

					return success(bertlv.Append(nil, 0x6e, value)), nil
				case byte(protocol.GenerateAsymmetricKeyPair):
					if command.P1 != 0x81 || !bytes.Equal(command.Data, []byte{0xb6, 0}) {
						t.Errorf("public-key command = %+v", command)
					}

					value := bertlv.Append(nil, 0x81, software.N.Bytes())
					value = bertlv.Append(value, 0x82, big.NewInt(int64(software.E)).Bytes())

					return success(bertlv.Append(nil, 0x7f49, value)), nil
				case byte(protocol.Verify):
					if command.P1 != 0 || command.P2 != 0x81 || !bytes.Equal(command.Data, password) {
						t.Errorf("VERIFY = %+v", command)
					}

					return success(nil), nil
				case byte(protocol.PerformSecurityOperation):
					if command.P1 != 0x9e || command.P2 != 0x9a || !bytes.Equal(command.Data, wantInput) {
						t.Errorf("signature input = %x, want %x", command.Data, wantInput)
					}

					signature, err := rsa.SignPKCS1v15(rand.Reader, software, test.hash, digest)

					return success(signature), err
				default:
					return iso7816.Response{}, fmt.Errorf("unexpected command %02x", command.INS)
				}
			}})

			t.Cleanup(func() { _ = d.Close() })

			key, err := d.PrivateKey(t.Context(), protocol.DigitalSignatureTemplateTag)
			if err != nil {
				t.Fatal(err)
			}

			var supplied []byte

			signer := key.Signer(t.Context(), func(context.Context) ([]byte, error) {
				supplied = slices.Clone(password)
				return supplied, nil
			})

			signature, err := signer.Sign(nil, digest, test.hash)
			if err != nil {
				t.Fatal(err)
			}

			if err := rsa.VerifyPKCS1v15(signer.Public().(*rsa.PublicKey), test.hash, digest, signature); err != nil {
				t.Errorf("signature: %v", err)
			}

			if !bytes.Equal(supplied, make([]byte, len(supplied))) {
				t.Error("authentication buffer was not cleared")
			}

			if len(commands) != 4 || commands[2].INS != 0x20 || commands[3].INS != 0x2a {
				t.Errorf("command sequence = %+v", commands)
			}
		})
	}
}
