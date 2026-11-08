package client_test

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestImportKeyWithTemplateWire(t *testing.T) {
	key, attributes, material := keyImportP256Fixture(t)

	for _, test := range []struct {
		name     string
		template protocol.ControlReferenceTemplate
		options  []client.Option
		header   []byte
	}{
		{
			name:     "short CRT short APDU",
			template: protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag},
			header:   []byte{0, 0xdb, 0x3f, 0xff, 0x6f, 0x4d, 0x6d, 0xb6, 0, 0x7f, 0x48, 4, 0x92, 0x20, 0x99, 0x41, 0x5f, 0x48, 0x61},
		},
		{
			name:     "extended CRT short APDU",
			template: protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag, KeyReference: protocol.SignatureKeyReference},
			header:   []byte{0, 0xdb, 0x3f, 0xff, 0x72, 0x4d, 0x70, 0xb6, 3, 0x84, 1, 1, 0x7f, 0x48, 4, 0x92, 0x20, 0x99, 0x41, 0x5f, 0x48, 0x61},
		},
		{
			name:     "short CRT extended APDU",
			template: protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag},
			options:  []client.Option{client.WithExtendedLength()},
			header:   []byte{0, 0xdb, 0x3f, 0xff, 0, 0, 0x6f, 0x4d, 0x6d, 0xb6, 0, 0x7f, 0x48, 4, 0x92, 0x20, 0x99, 0x41, 0x5f, 0x48, 0x61},
		},
		{
			name:     "extended CRT extended APDU",
			template: protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag, KeyReference: protocol.SignatureKeyReference},
			options:  []client.Option{client.WithExtendedLength()},
			header:   []byte{0, 0xdb, 0x3f, 0xff, 0, 0, 0x72, 0x4d, 0x70, 0xb6, 3, 0x84, 1, 1, 0x7f, 0x48, 4, 0x92, 0x20, 0x99, 0x41, 0x5f, 0x48, 0x61},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := slices.Concat(test.header, material)

			t.Cleanup(func() { clear(want) })
			p := &keyImportPeer{t: t, want: want, response: iso7816.Response{Status: 0x9000}}
			c := client.NewClient(p, test.options...)

			if err := c.ImportKeyWithTemplate(t.Context(), test.template, attributes, key); err != nil {
				t.Fatal(err)
			}

			checkKeyImportCleared(t, p)
		})
	}
}

func TestImportKeyReadsCurrentStandardAttributes(t *testing.T) {
	key, _, material := keyImportP256Fixture(t)
	// signatureApplication announces private-only P-256 import, rather than FF.
	command := slices.Concat([]byte{
		0, 0xdb, 0x3f, 0xff, 0x2c,
		0x4d, 0x2a, 0xb6, 0, 0x7f, 0x48, 2, 0x92, 0x20, 0x5f, 0x48, 0x20,
	}, material[:32])

	t.Cleanup(func() { clear(command) })
	c := newClient(t,
		step{command: []byte{0, 0xca, 0, 0x6e, 0}, response: iso7816.Response{Status: 0x9000, Data: signatureApplication}},
		step{command: command, response: iso7816.Response{Status: 0x9000}},
	)

	if err := c.ImportKey(t.Context(), protocol.DigitalSignatureTemplateTag, key); err != nil {
		t.Fatal(err)
	}
}

func TestImport25519PrivateBytesAndPublicWire(t *testing.T) {
	seed := make([]byte, 32)

	for i := range seed {
		seed[i] = byte(i + 1)
	}
	defer clear(seed)

	edKey := ed25519.NewKeyFromSeed(seed)
	defer clear(edKey)

	edBefore := slices.Clone(edKey)
	defer clear(edBefore)

	xKey, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	xBefore := xKey.Bytes()
	defer clear(xBefore)

	xWire := []byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	defer clear(xWire)

	for _, algorithm := range []struct {
		name      string
		key       crypto.PrivateKey
		reference protocol.ControlReferenceTemplateTag
		algorithm protocol.Algorithm
		oid       []byte
		private   []byte
		public    []byte
	}{
		{
			name: "Ed25519 seed", key: edKey, reference: protocol.DigitalSignatureTemplateTag,
			algorithm: protocol.EdDSA, oid: []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01},
			private: seed, public: edKey.Public().(ed25519.PublicKey),
		},
		{
			name: "X25519 big-endian scalar", key: xKey, reference: protocol.ConfidentialityTemplateTag,
			algorithm: protocol.ECDH, oid: []byte{0x2b, 0x65, 0x6e},
			private: xWire, public: xKey.PublicKey().Bytes(),
		},
	} {
		t.Run(algorithm.name, func(t *testing.T) {
			for _, format := range []struct {
				name   string
				format protocol.ImportFormat
				header []byte
			}{
				{
					name: "private only",
					header: []byte{
						0, 0xdb, 0x3f, 0xff, 0x2c,
						0x4d, 0x2a, byte(algorithm.reference), 0, 0x7f, 0x48, 2, 0x92, 0x20, 0x5f, 0x48, 0x20,
					},
				},
				{
					name: "with encoded public", format: 0xff,
					header: []byte{
						0, 0xdb, 0x3f, 0xff, 0x4f,
						0x4d, 0x4d, byte(algorithm.reference), 0, 0x7f, 0x48, 4, 0x92, 0x20, 0x99, 0x21, 0x5f, 0x48, 0x41,
					},
				},
			} {
				t.Run(format.name, func(t *testing.T) {
					var want []byte
					if format.format == 0xff {
						want = slices.Concat(format.header, algorithm.private, []byte{0x40}, algorithm.public)
					} else {
						want = slices.Concat(format.header, algorithm.private)
					}
					defer clear(want)

					p := &keyImportPeer{t: t, want: want, response: iso7816.Response{Status: 0x9000}}
					c := client.NewClient(p)

					if err := c.ImportKeyWithTemplate(t.Context(), protocol.ControlReferenceTemplate{
						Tag: algorithm.reference,
					}, protocol.AlgorithmAttributes{
						Algorithm: algorithm.algorithm, CurveOID: algorithm.oid, ImportFormat: format.format,
					}, algorithm.key); err != nil {
						t.Fatal(err)
					}

					checkKeyImportCleared(t, p)
				})
			}
		})
	}

	if !bytes.Equal(edKey, edBefore) {
		t.Error("import modified the borrowed Ed25519 private key")
	}

	xAfter := xKey.Bytes()
	defer clear(xAfter)

	if !bytes.Equal(xAfter, xBefore) {
		t.Error("import modified the borrowed X25519 private key")
	}
}

func TestImportRSAFramePreservesBorrowedKey(t *testing.T) {
	generated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// A valid RSA key need not have its optional precomputation cache populated.
	key := &rsa.PrivateKey{PublicKey: generated.PublicKey, D: generated.D, Primes: generated.Primes}
	beforeN := new(big.Int).Set(key.N)
	beforeD := new(big.Int).Set(key.D)
	beforeP := new(big.Int).Set(key.Primes[0])
	beforeQ := new(big.Int).Set(key.Primes[1])

	t.Cleanup(func() {
		clear(beforeD.Bits())
		clear(beforeP.Bits())
		clear(beforeQ.Bits())
	})

	material := make([]byte, 4+128+128)
	defer clear(material)

	binary.BigEndian.PutUint32(material[:4], uint32(key.E))
	key.Primes[0].FillBytes(material[4:132])
	key.Primes[1].FillBytes(material[132:])
	// Standard RSA format 0: e4 || p128 || q128, with DOL headers only.
	want := slices.Concat([]byte{
		0, 0xdb, 0x3f, 0xff, 0, 0x01, 0x1a,
		0x4d, 0x82, 0x01, 0x16, 0xb8, 0,
		0x7f, 0x48, 8, 0x91, 4, 0x92, 0x81, 0x80, 0x93, 0x81, 0x80,
		0x5f, 0x48, 0x82, 0x01, 0x04,
	}, material)
	defer clear(want)

	p := &keyImportPeer{t: t, want: want, response: iso7816.Response{Status: 0x9000}}
	c := client.NewClient(p, client.WithExtendedLength())

	if err := c.ImportKeyWithTemplate(t.Context(), protocol.ControlReferenceTemplate{
		Tag: protocol.ConfidentialityTemplateTag,
	}, protocol.AlgorithmAttributes{
		Algorithm: protocol.RSA, ModulusBits: 2048, ExponentBits: 32, ImportFormat: 0,
	}, key); err != nil {
		t.Fatal(err)
	}

	checkKeyImportCleared(t, p)

	if key.N.Cmp(beforeN) != 0 || key.D.Cmp(beforeD) != 0 || key.E != generated.E ||
		len(key.Primes) != 2 || key.Primes[0].Cmp(beforeP) != 0 || key.Primes[1].Cmp(beforeQ) != 0 {
		t.Error("import modified the borrowed RSA key")
	}

	if !reflect.ValueOf(key.Precomputed).IsZero() {
		t.Error("import populated the borrowed RSA precomputation cache")
	}
}

func TestImportFailureClearsPayloadAndPreservesEffectIdentity(t *testing.T) {
	key, attributes, material := keyImportP256Fixture(t)
	template := protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag, KeyReference: protocol.KeyReference(0x82)}

	for _, test := range []struct {
		name         string
		response     iso7816.Response
		err          error
		acknowledged bool
	}{
		{name: "malformed acknowledgement", response: iso7816.Response{Status: 0x9000, Data: []byte{1}}, acknowledged: true},
		{name: "APDU rejection", response: iso7816.Response{Status: 0x6982}},
		{name: "transport failure", err: io.ErrUnexpectedEOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := slices.Concat([]byte{
				0, 0xdb, 0x3f, 0xff, 0x72,
				0x4d, 0x70, 0xb6, 3, 0x84, 1, 0x82,
				0x7f, 0x48, 4, 0x92, 0x20, 0x99, 0x41, 0x5f, 0x48, 0x61,
			}, material)
			defer clear(want)

			p := &keyImportPeer{t: t, want: want, response: test.response, err: test.err}
			c := client.NewClient(p)

			err := c.ImportKeyWithTemplate(t.Context(), template, attributes, key)

			checkKeyImportCleared(t, p)

			var imported *client.KeyImportError
			if test.acknowledged {
				if !errors.As(err, &imported) || imported.Template != template || !errors.Is(err, protocol.ErrInvalidResponse) {
					t.Fatalf("error = %v, want acknowledged replacement of %+v", err, template)
				}

				if !strings.Contains(imported.Error(), "b603840182") {
					t.Errorf("error = %q, want complete requested CRT", imported.Error())
				}

				return
			}

			if err == nil || errors.As(err, &imported) {
				t.Fatalf("error = %v, want ordinary unacknowledged failure", err)
			}

			if test.err != nil {
				if !errors.Is(err, test.err) {
					t.Errorf("error = %v, want transport cause %v", err, test.err)
				}
			} else {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6982 {
					t.Errorf("error = %v, want APDU status 6982", err)
				}
			}
		})
	}
}

func TestImportMismatchAndUnsupportedAlgorithmPrecedeIO(t *testing.T) {
	key, _, _ := keyImportP256Fixture(t)

	for _, test := range []struct {
		name       string
		attributes protocol.AlgorithmAttributes
		want       error
	}{
		{
			name: "key family mismatch",
			attributes: protocol.AlgorithmAttributes{
				Algorithm: protocol.RSA, ModulusBits: 2048, ExponentBits: 32,
			},
			want: protocol.ErrKeyMismatch,
		},
		{
			name: "curve mismatch",
			attributes: protocol.AlgorithmAttributes{
				Algorithm: protocol.ECDSA, CurveOID: []byte{0x2b, 0x81, 0x04, 0x00, 0x22},
			},
			want: protocol.ErrKeyMismatch,
		},
		{
			name:       "unknown card algorithm",
			attributes: protocol.AlgorithmAttributes{Algorithm: 99},
			want:       protocol.ErrUnsupportedAlgorithm,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := newClient(t)

			err := c.ImportKeyWithTemplate(t.Context(), protocol.ControlReferenceTemplate{
				Tag: protocol.DigitalSignatureTemplateTag, KeyReference: protocol.SignatureKeyReference,
			}, test.attributes, key)

			var imported *client.KeyImportError
			if !errors.Is(err, test.want) || errors.As(err, &imported) {
				t.Fatalf("error = %v, want pre-effect %v", err, test.want)
			}
		})
	}
}
