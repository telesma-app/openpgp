package card

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"math/big"
	"slices"
	"testing"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/openpgp/protocol"
)

func TestDECSignerUsesBoundKeyAndPW1Reference(t *testing.T) {
	decryption, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	authentication, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte("DEC key used for internal authentication"))
	// DigestInfo from OpenPGP Card 3.4.1, Sec. 7.2.10.2.
	wantInput := append(decodeHex(t, "3031300d060960864801650304020105000420"), digest[:]...)
	attributes := bertlv.Append(nil, 0xc2, []byte{0x01, 0x08, 0x00, 0x00, 0x20, 0x00})
	application := bertlv.Append(nil, 0x4f, decodeHex(t, "d2760001240103040006000000010000"))
	application = append(application, bertlv.Append(nil, 0x73, attributes)...)
	application = bertlv.Append(nil, 0x6e, application)
	public := bertlv.Append(nil, 0x81, decryption.N.Bytes())
	public = bertlv.Append(public, 0x82, big.NewInt(int64(decryption.E)).Bytes())
	public = bertlv.Append(nil, 0x7f49, public)

	for _, test := range []struct {
		name  string
		key   *rsa.PrivateKey
		wrong bool
	}{
		{name: "DEC signature", key: decryption},
		{name: "AUT signature rejected", key: authentication, wrong: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			response, err := rsa.SignPKCS1v15(rand.Reader, test.key, crypto.SHA256, digest[:])
			if err != nil {
				t.Fatal(err)
			}

			d, peer := newMSEDevice(t, nil,
				mseScriptStep{command: []byte{0x00, 0xca, 0x00, 0x6e, 0x00}, response: success(application)},
				mseScriptStep{command: []byte{0x00, 0x47, 0x81, 0x00, 0x02, 0xb8, 0x00, 0x00}, response: success(public)},
				mseScriptStep{command: []byte{0x00, 0x20, 0x00, 0x82, 0x06, '1', '2', '3', '4', '5', '6'}, response: success(nil)},
				mseScriptStep{command: []byte{0x00, 0x22, 0x41, 0xa4, 0x03, 0x83, 0x01, 0x02}, response: success(nil)},
				mseScriptStep{command: slices.Concat([]byte{0x00, 0x88, 0x00, 0x00, 0x33}, wantInput, []byte{0x00}), response: success(response)},
				mseScriptStep{command: []byte{0x00, 0x22, 0x41, 0xa4, 0x03, 0x83, 0x01, 0x03}, response: success(nil)},
				mseScriptStep{command: []byte{0x00, 0x88, 0x00, 0x00, 0x01, 0x01, 0x00}, response: success([]byte{0x03})},
			)

			key, err := d.PrivateKey(t.Context(), protocol.ConfidentialityTemplateTag)
			if err != nil {
				t.Fatal(err)
			}

			bound, ok := key.Public().(*rsa.PublicKey)
			if !ok || bound.N.Cmp(decryption.N) != 0 || bound.E != decryption.E {
				t.Fatalf("bound public key = %v, want DEC public key", key.Public())
			}

			password := []byte("123456")

			var sourceCalls int

			signer := key.Signer(t.Context(), func(context.Context) ([]byte, error) {
				sourceCalls++
				return password, nil
			})

			got, err := signer.Sign(nil, digest[:], crypto.SHA256)

			if test.wrong {
				if !errors.Is(err, protocol.ErrInvalidResponse) || got != nil {
					t.Errorf("Sign = %x, %v; want invalid response and nil signature", got, err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}

				if err := rsa.VerifyPKCS1v15(bound, crypto.SHA256, digest[:], got); err != nil {
					t.Errorf("DEC signature verification: %v", err)
				}
			}

			if sourceCalls != 1 || !bytes.Equal(password, make([]byte, len(password))) {
				t.Errorf("authentication source calls = %d, cleared = %v; want one call and cleared password", sourceCalls, bytes.Equal(password, make([]byte, len(password))))
			}

			if peer.closes != 0 {
				t.Errorf("Close calls = %d, want open connection after restoration", peer.closes)
			}

			got, err = d.InternalAuthenticate(t.Context(), []byte{0x01}, nil)
			if err != nil || !bytes.Equal(got, []byte{0x03}) {
				t.Errorf("default authentication after signing = %x, %v; want AUT result 03", got, err)
			}
		})
	}
}
