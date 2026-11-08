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

func hardwarePassword(t testing.TB, variable string) []byte {
	t.Helper()

	encoded := os.Getenv(variable)
	if encoded == "" {
		t.Fatalf("%s must contain an explicitly configured password as hexadecimal bytes", variable)
	}

	password, err := hex.DecodeString(encoded)
	if err != nil {
		clear(password)
		t.Fatalf("%s must contain valid hexadecimal bytes", variable)
	}

	t.Cleanup(func() { clear(password) })

	return password
}

func verifyHardwareCredentials(t testing.TB, ctx context.Context, device *card.Device, password, adminPassword []byte) {
	t.Helper()

	if err := device.Verify(ctx, protocol.PW3, adminPassword); err != nil {
		t.Fatalf("verify configured PW3: %v", err)
	}

	if err := device.Verify(ctx, protocol.PW1, password); err != nil {
		t.Fatalf("verify configured PW1: %v", err)
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

func resetHardwareApplication(t *testing.T, reader string, adminPassword []byte) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	connection, err := openpgppcsc.Open(ctx, reader)
	if err != nil {
		t.Errorf("reopen selected reader for MSE factory reset: %v", err)
		return
	}

	device := card.New(connection)
	defer func() {
		if err := device.Close(); err != nil {
			t.Errorf("close MSE factory-reset connection: %v", err)
		}
	}()

	if err := device.Verify(ctx, protocol.PW3, adminPassword); err != nil {
		t.Errorf("verify configured PW3 for MSE factory reset: %v", err)
		return
	}

	if err := device.TerminateDF(ctx, nil); err != nil {
		t.Errorf("terminate MSE test application: %v", err)
		return
	}

	if err := device.Close(); err != nil {
		t.Errorf("close terminated MSE application: %v", err)
	}

	connection, err = openpgppcsc.Open(ctx, reader)
	if err != nil {
		t.Errorf("reopen terminated MSE application: %v", err)
		return
	}

	device = card.New(connection)
	if err := device.ActivateFile(ctx); err != nil {
		t.Errorf("activate MSE test application: %v", err)
		return
	}

	data, err := device.GetData(ctx, protocol.KeyInformationObject)
	if err != nil {
		t.Errorf("read key information after MSE factory reset: %v", err)
		return
	}

	keys, err := protocol.ParseKeyInformation(data)
	if err != nil {
		t.Errorf("parse key information after MSE factory reset: %v", err)
		return
	}

	for i, key := range keys[:3] {
		if byte(key.Reference) != byte(i+1) {
			t.Errorf("key reference %d = %d, want %d", i, key.Reference, i+1)
		}

		if key.Status != 0 {
			t.Errorf("key %d status after MSE factory reset = %d, want absent", key.Reference, key.Status)
		}
	}

	certificates, err := device.GetCardholderCertificates(ctx)
	if err != nil {
		t.Errorf("read certificates after MSE factory reset: %v", err)
		return
	}

	checkHardwareCertificates(t, certificates, protocol.CardholderCertificates{})
}
