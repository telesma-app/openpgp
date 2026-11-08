package pcsc_test

import (
	"bytes"
	"context"
	"encoding/hex"
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
