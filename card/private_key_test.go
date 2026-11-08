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
	"errors"
	"slices"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

const (
	ed25519RFC8032PublicHex    = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
	ed25519RFC8032SignatureHex = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
)

func TestPrivateKeyECDSAConvertsAndVerifiesSignature(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
				t.Run(hash.String(), func(t *testing.T) {
					software, err := ecdsa.GenerateKey(curve, rand.Reader)
					if err != nil {
						t.Fatal(err)
					}

					digestHash := hash.New()
					digestHash.Write([]byte("digest"))
					digest := digestHash.Sum(nil)
					d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
						if command.INS != 0x88 || command.P1 != 0 || command.P2 != 0 || !bytes.Equal(command.Data, digest) {
							t.Errorf("authentication command = %+v", command)
						}

						r, s, err := ecdsa.Sign(rand.Reader, software, digest)
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

					signature, err := key.Sign(t.Context(), digest, hash, nil)
					if err != nil {
						t.Fatal(err)
					}

					if !ecdsa.VerifyASN1(&software.PublicKey, digest, signature) {
						t.Errorf("signature = %x is not valid ASN.1 ECDSA", signature)
					}
				})
			}
		})
	}
}

func TestPrivateKeyEd25519RFC8032(t *testing.T) {
	// RFC 8032, Section 7.1, TEST 2. The input is a one-byte message,
	// not its digest and not an Ed25519ph prehash.
	for _, test := range []struct {
		name string
		opts crypto.SignerOpts
	}{
		{name: "hash zero", opts: crypto.Hash(0)},
		{name: "empty options", opts: &ed25519.Options{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			public := ed25519.PublicKey(decodeHex(t, ed25519RFC8032PublicHex))
			want := decodeHex(t, ed25519RFC8032SignatureHex)
			d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				if command.INS != 0x2a || !bytes.Equal(command.Data, []byte{0x72}) {
					t.Errorf("Ed25519 command = %+v", command)
				}

				return success(slices.Clone(want)), nil
			}})

			t.Cleanup(func() { _ = d.Close() })

			key := &PrivateKey{device: d, templateTag: protocol.DigitalSignatureTemplateTag, publicKey: public}

			signature, err := key.Sign(t.Context(), []byte{0x72}, test.opts, nil)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(signature, want) {
				t.Errorf("signature = %x, want %x", signature, want)
			}
		})
	}
}

func TestPrivateKeyEd25519RejectsInvalidSignature(t *testing.T) {
	// Derive invalid responses from RFC 8032, Section 7.1, TEST 2.
	// The different public key is from TEST 1 in the same section.
	for _, test := range []struct {
		name         string
		publicHex    string
		messageHex   string
		signatureHex string
	}{
		{
			name: "tampered signature", publicHex: ed25519RFC8032PublicHex, messageHex: "72",
			signatureHex: "93" + ed25519RFC8032SignatureHex[2:],
		},
		{
			name: "different public key", messageHex: "72", signatureHex: ed25519RFC8032SignatureHex,
			publicHex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
		},
		{
			name: "different message", publicHex: ed25519RFC8032PublicHex, messageHex: "73",
			signatureHex: ed25519RFC8032SignatureHex,
		},
		{
			name: "empty signature", publicHex: ed25519RFC8032PublicHex, messageHex: "72",
		},
		{
			name: "short signature", publicHex: ed25519RFC8032PublicHex, messageHex: "72",
			signatureHex: ed25519RFC8032SignatureHex[:len(ed25519RFC8032SignatureHex)-2],
		},
		{
			name: "long signature", publicHex: ed25519RFC8032PublicHex, messageHex: "72",
			signatureHex: ed25519RFC8032SignatureHex + "00",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			public := ed25519.PublicKey(decodeHex(t, test.publicHex))
			message := decodeHex(t, test.messageHex)
			response := decodeHex(t, test.signatureHex)
			calls := 0
			d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				calls++

				if command.INS != 0x2a || command.P1 != 0x9e || command.P2 != 0x9a || !bytes.Equal(command.Data, message) {
					t.Errorf("Ed25519 command = %+v, want PSO: COMPUTE DIGITAL SIGNATURE with message %x", command, message)
				}

				return success(response), nil
			}})

			t.Cleanup(func() { _ = d.Close() })

			key := &PrivateKey{device: d, templateTag: protocol.DigitalSignatureTemplateTag, publicKey: public}

			signature, err := key.Sign(t.Context(), message, crypto.Hash(0), nil)
			if !errors.Is(err, protocol.ErrInvalidResponse) || signature != nil {
				t.Errorf("Sign = %x, %v, want invalid response and nil signature", signature, err)
			}

			if calls != 1 {
				t.Errorf("exchange calls = %d, want 1", calls)
			}
		})
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

func TestPrivateKeyRejectsDigestLengthBeforeAuthentication(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	scalar := [32]byte{31: 1}

	ecKey, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar[:])
	if err != nil {
		t.Fatal(err)
	}

	for _, algorithm := range []struct {
		name   string
		public crypto.PublicKey
	}{
		{name: "RSA", public: &rsaKey.PublicKey},
		{name: "ECDSA", public: &ecKey.PublicKey},
	} {
		t.Run(algorithm.name, func(t *testing.T) {
			for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
				t.Run(hash.String(), func(t *testing.T) {
					for _, test := range []struct {
						name   string
						length int
					}{
						{name: "short", length: hash.Size() - 1},
						{name: "long", length: hash.Size() + 1},
					} {
						t.Run(test.name, func(t *testing.T) {
							var calls, sourceCalls int

							d := New(&exchangeTransport{exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
								calls++
								return success(nil), nil
							}})

							t.Cleanup(func() { _ = d.Close() })

							key := &PrivateKey{device: d, templateTag: protocol.DigitalSignatureTemplateTag, publicKey: algorithm.public}

							got, err := key.Sign(t.Context(), make([]byte, test.length), hash, func(context.Context) ([]byte, error) {
								sourceCalls++
								return []byte("123456"), nil
							})

							if err == nil || got != nil {
								t.Errorf("signature = %x, %v; want nil and invalid digest length", got, err)
							}

							if calls != 0 || sourceCalls != 0 {
								t.Errorf("exchanges=%d source calls=%d; want rejection before authentication and I/O", calls, sourceCalls)
							}
						})
					}
				})
			}
		})
	}
}

func TestPrivateKeyEd25519RejectsOptionsBeforeAuthentication(t *testing.T) {
	for _, test := range []struct {
		name string
		opts crypto.SignerOpts
	}{
		{name: "context", opts: &ed25519.Options{Context: "OpenPGP"}},
		{name: "prehashed message", opts: crypto.SHA512},
		{name: "prehash options", opts: &ed25519.Options{Hash: crypto.SHA512}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls, sourceCalls int

			d := New(&exchangeTransport{exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
				calls++
				return success(decodeHex(t, ed25519RFC8032SignatureHex)), nil
			}})

			t.Cleanup(func() { _ = d.Close() })

			key := &PrivateKey{
				device: d, templateTag: protocol.DigitalSignatureTemplateTag,
				publicKey: ed25519.PublicKey(decodeHex(t, ed25519RFC8032PublicHex)),
			}

			got, err := key.Sign(t.Context(), []byte{0x72}, test.opts, func(context.Context) ([]byte, error) {
				sourceCalls++
				return []byte("123456"), nil
			})

			if err == nil || got != nil {
				t.Errorf("signature = %x, %v; want nil and unsupported Ed25519 options", got, err)
			}

			if calls != 0 || sourceCalls != 0 {
				t.Errorf("exchanges=%d source calls=%d; want rejection before authentication and I/O", calls, sourceCalls)
			}
		})
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
