package card

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"testing"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

func TestPrivateKeyRSASigner(t *testing.T) {
	software, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte("OpenPGP Card signing"))
	// DigestInfo prefix from OpenPGP Card 3.4.1, Section 7.2.10.2.
	wantInput := append(unhex(t, "3031300d060960864801650304020105000420"), digest[:]...)
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
			value = append(bertlv.Append(nil, 0x4f, unhex(t, "d2760001240103040006000000010000")), value...)

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

			signature, err := rsa.SignPKCS1v15(rand.Reader, software, crypto.SHA256, digest[:])

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

	signature, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	if err := rsa.VerifyPKCS1v15(signer.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], signature); err != nil {
		t.Errorf("signature: %v", err)
	}

	if !bytes.Equal(supplied, make([]byte, len(supplied))) {
		t.Error("authentication buffer was not cleared")
	}

	if len(commands) != 4 || commands[2].INS != 0x20 || commands[3].INS != 0x2a {
		t.Errorf("command sequence = %+v", commands)
	}
}

func TestPrivateKeyECDSAConvertsAndVerifiesSignature(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			software, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			digest := sha256.Sum256([]byte("digest"))
			d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				if command.INS != 0x88 || command.P1 != 0 || command.P2 != 0 || !bytes.Equal(command.Data, digest[:]) {
					t.Errorf("authentication command = %+v", command)
				}

				r, s, err := ecdsa.Sign(rand.Reader, software, digest[:])
				if err != nil {
					return iso7816.Response{}, err
				}

				width := (curve.Params().N.BitLen() + 7) / 8
				raw := make([]byte, 2*width)
				r.FillBytes(raw[:width])
				s.FillBytes(raw[width:])

				return success(raw), nil
			}})

			t.Cleanup(func() { _ = d.Close() })

			key := &PrivateKey{device: d, templateTag: protocol.AuthenticationTemplateTag, publicKey: &software.PublicKey}

			signature, err := key.Sign(t.Context(), digest[:], crypto.SHA256, nil)
			if err != nil {
				t.Fatal(err)
			}

			if !ecdsa.VerifyASN1(&software.PublicKey, digest[:], signature) {
				t.Errorf("signature = %x is not valid ASN.1 ECDSA", signature)
			}
		})
	}
}

func TestPrivateKeyEd25519RFC8032(t *testing.T) {
	// RFC 8032, Section 7.1, TEST 2. The input is a one-byte message,
	// not its digest and not an Ed25519ph prehash.
	public := ed25519.PublicKey(unhex(t, "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"))
	want := unhex(t, "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
	d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
		if command.INS != 0x2a || !bytes.Equal(command.Data, []byte{0x72}) {
			t.Errorf("Ed25519 command = %+v", command)
		}

		return success(slices.Clone(want)), nil
	}})

	t.Cleanup(func() { _ = d.Close() })

	key := &PrivateKey{device: d, templateTag: protocol.DigitalSignatureTemplateTag, publicKey: public}

	signature, err := key.Sign(t.Context(), []byte{0x72}, crypto.Hash(0), nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(signature, want) {
		t.Errorf("signature = %x, want %x", signature, want)
	}
}

func TestPrivateKeyRejectsOptionsBeforeAuthentication(t *testing.T) {
	software, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	d := New(&exchangeTransport{exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
		t.Error("unexpected I/O for unsupported options")
		return iso7816.Response{}, errors.New("unexpected I/O")
	}})

	t.Cleanup(func() { _ = d.Close() })

	key := &PrivateKey{device: d, templateTag: protocol.DigitalSignatureTemplateTag, publicKey: &software.PublicKey}
	for _, opts := range []crypto.SignerOpts{&rsa.PSSOptions{Hash: crypto.SHA256}, crypto.SHA1, crypto.Hash(0)} {
		_, err := key.Sign(t.Context(), make([]byte, 32), opts, func(context.Context) ([]byte, error) {
			t.Error("authentication called for unsupported options")
			return nil, errors.New("unexpected authentication")
		})
		if err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
}

func TestPrivateKeyRejectsInvalidExternalSignature(t *testing.T) {
	software, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, signature := range [][]byte{make([]byte, 63), make([]byte, 64)} {
		d := New(&exchangeTransport{exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
			return success(signature), nil
		}})

		t.Cleanup(func() { _ = d.Close() })

		key := &PrivateKey{device: d, templateTag: protocol.DigitalSignatureTemplateTag, publicKey: &software.PublicKey}

		got, err := key.Sign(t.Context(), make([]byte, 32), crypto.SHA256, nil)
		if !errors.Is(err, protocol.ErrInvalidResponse) || got != nil {
			t.Errorf("Sign = %x, %v, want invalid response and nil signature", got, err)
		}
	}
}

func success(data []byte) iso7816.Response {
	return iso7816.Response{Data: data, Status: iso7816.StatusSuccess}
}

func unhex(t testing.TB, value string) []byte {
	t.Helper()

	data, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}

	return data
}
