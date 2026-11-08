package pcsc_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"os"
	"testing"
	"time"

	openpgppcsc "github.com/telesma-app/openpgp/backend/pcsc"
	"github.com/telesma-app/openpgp/card"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

// TestHardwareWriteCertificates replaces and clears certificates, then restores
// them through a fresh connection. Keys and passwords are unchanged. PW3 must
// include any KDF; an incorrect value can consume a retry.
func TestHardwareWriteCertificates(t *testing.T) {
	if os.Getenv("OPENPGP_TEST_WRITE") != "1" {
		t.Skip("set OPENPGP_TEST_WRITE=1 to modify certificates on a selected test card")
	}

	reader := os.Getenv("OPENPGP_TEST_READER")
	if reader == "" {
		t.Fatal("OPENPGP_TEST_READER must name one exact reader")
	}

	encodedPW3 := os.Getenv("OPENPGP_TEST_PW3_HEX")
	if encodedPW3 == "" {
		t.Fatal("OPENPGP_TEST_PW3_HEX must contain the encoded PW3 as hexadecimal bytes")
	}

	password, err := hex.DecodeString(encodedPW3)
	if err != nil {
		t.Fatal("OPENPGP_TEST_PW3_HEX must contain valid hexadecimal bytes")
	}

	t.Cleanup(func() { clear(password) })

	certificates := protocol.CardholderCertificates{
		Authentication: newHardwareCertificate(t, 1, "AUT"),
		Decryption:     newHardwareCertificate(t, 2, "DEC"),
		Signature:      newHardwareCertificate(t, 3, "SIG"),
	}

	for _, test := range []struct {
		name    string
		options []client.Option
	}{
		{name: "short", options: []client.Option{client.WithEmptyPutDataLe()}},
		{name: "extended", options: []client.Option{client.WithExtendedLength(), client.WithEmptyPutDataLe()}},
	} {
		if !t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()

			connection, err := openpgppcsc.Open(ctx, reader)
			if err != nil {
				t.Fatal(err)
			}

			device := card.New(connection, test.options...)
			cleanup := func() {
				if err := device.Close(); err != nil {
					t.Errorf("close test connection: %v", err)
				}
			}

			t.Cleanup(func() { cleanup() })

			original, err := device.GetCardholderCertificates(ctx)
			if err != nil {
				t.Fatalf("snapshot certificates: %v", err)
			}

			if err := device.Verify(ctx, protocol.PW3, password); err != nil {
				t.Fatalf("verify configured PW3: %v", err)
			}

			cleanup = func() {
				if err := device.Close(); err != nil {
					t.Errorf("close test connection before restoration: %v", err)
				}

				restoreHardwareCertificates(t, reader, password, original)
			}

			for _, certificate := range []struct {
				name string
				key  protocol.ControlReferenceTemplateTag
				data []byte
			}{
				{name: "AUT", key: protocol.AuthenticationTemplateTag, data: certificates.Authentication},
				{name: "DEC", key: protocol.ConfidentialityTemplateTag, data: certificates.Decryption},
				{name: "SIG", key: protocol.DigitalSignatureTemplateTag, data: certificates.Signature},
			} {
				if err := device.PutCardholderCertificate(ctx, certificate.key, certificate.data, nil); err != nil {
					t.Fatalf("write %s certificate: %v", certificate.name, err)
				}
			}

			signature, err := device.GetCardholderCertificate(ctx, protocol.DigitalSignatureTemplateTag)
			if err != nil {
				t.Fatalf("read SIG certificate: %v", err)
			}

			if !bytes.Equal(signature, certificates.Signature) {
				t.Error("SIG certificate differs from the written bytes")
			}

			got, err := device.GetCardholderCertificates(ctx)
			if err != nil {
				t.Fatalf("traverse certificates after selecting SIG: %v", err)
			}

			checkHardwareCertificates(t, got, certificates)

			if err := device.PutCardholderCertificate(ctx, protocol.ConfidentialityTemplateTag, nil, nil); err != nil {
				t.Fatalf("clear DEC certificate: %v", err)
			}

			got, err = device.GetCardholderCertificates(ctx)
			if err != nil {
				t.Fatalf("traverse certificates with empty DEC: %v", err)
			}

			checkHardwareCertificates(t, got, protocol.CardholderCertificates{
				Authentication: certificates.Authentication,
				Signature:      certificates.Signature,
			})
		}) {
			return
		}
	}
}

func newHardwareCertificate(t testing.TB, serial int64, name string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:   "OpenPGP hardware certificate " + name,
			Organization: []string{"telesma-app OpenPGP hardware tests"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	if len(der) <= 256 || len(der) >= 2048 {
		t.Fatalf("%s fixture certificate length = %d, want 257..2047 bytes", name, len(der))
	}

	return der
}

func restoreHardwareCertificates(t *testing.T, reader string, password []byte, original protocol.CardholderCertificates) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	connection, err := openpgppcsc.Open(ctx, reader)
	if err != nil {
		t.Errorf("reopen selected reader for certificate restoration: %v", err)
		return
	}

	device := card.New(connection, client.WithEmptyPutDataLe())
	defer func() {
		if err := device.Close(); err != nil {
			t.Errorf("close restoration connection: %v", err)
		}
	}()

	if err := device.Verify(ctx, protocol.PW3, password); err != nil {
		t.Errorf("verify configured PW3 for certificate restoration: %v", err)
		return
	}

	for _, certificate := range []struct {
		name string
		key  protocol.ControlReferenceTemplateTag
		data []byte
	}{
		{name: "AUT", key: protocol.AuthenticationTemplateTag, data: original.Authentication},
		{name: "DEC", key: protocol.ConfidentialityTemplateTag, data: original.Decryption},
		{name: "SIG", key: protocol.DigitalSignatureTemplateTag, data: original.Signature},
	} {
		if err := device.PutCardholderCertificate(ctx, certificate.key, certificate.data, nil); err != nil {
			t.Errorf("restore %s certificate: %v", certificate.name, err)
		}
	}

	got, err := device.GetCardholderCertificates(ctx)
	if err != nil {
		t.Errorf("read restored certificates: %v", err)
		return
	}

	checkHardwareCertificates(t, got, original)
}

func checkHardwareCertificates(t testing.TB, got, want protocol.CardholderCertificates) {
	t.Helper()

	if !bytes.Equal(got.Authentication, want.Authentication) {
		t.Error("AUT certificate differs from expected bytes")
	}

	if !bytes.Equal(got.Decryption, want.Decryption) {
		t.Error("DEC certificate differs from expected bytes")
	}

	if !bytes.Equal(got.Signature, want.Signature) {
		t.Error("SIG certificate differs from expected bytes")
	}
}
