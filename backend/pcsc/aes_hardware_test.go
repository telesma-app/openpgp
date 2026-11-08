package pcsc_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	baseiso7816 "github.com/telesma-app/iso7816"
	openpgppcsc "github.com/telesma-app/openpgp/backend/pcsc"
	"github.com/telesma-app/openpgp/card"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

// TestHardwareAES provisions write-only D5 and tests PSO:ENCIPHER/DECIPHER on
// a disposable card. Cleanup factory-resets the entire OpenPGP application,
// erasing its keys, certificates, passwords and user data. It requires
// OPENPGP_TEST_WRITE=1, OPENPGP_TEST_RESET=1 and explicit encoded PW1/PW3.
func TestHardwareAES(t *testing.T) {
	if os.Getenv("OPENPGP_TEST_WRITE") != "1" {
		t.Skip("set OPENPGP_TEST_WRITE=1 to provision an AES key on a selected test card")
	}

	if os.Getenv("OPENPGP_TEST_RESET") != "1" {
		t.Skip("set OPENPGP_TEST_RESET=1 to permit factory reset of the entire OpenPGP application")
	}

	reader := os.Getenv("OPENPGP_TEST_READER")
	if reader == "" {
		t.Fatal("OPENPGP_TEST_READER must name one exact reader")
	}

	password := hardwareAESPassword(t, "OPENPGP_TEST_PW1_HEX")
	adminPassword := hardwareAESPassword(t, "OPENPGP_TEST_PW3_HEX")

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()

	connection, err := openpgppcsc.Open(ctx, reader)
	if err != nil {
		t.Fatal(err)
	}

	device := card.New(connection)
	cleanup := func() {
		if err := device.Close(); err != nil {
			t.Errorf("close AES test connection: %v", err)
		}
	}

	t.Cleanup(func() { cleanup() })

	application, err := device.GetApplicationRelatedData(ctx)
	if err != nil {
		t.Fatalf("read application capabilities: %v", err)
	}

	if application.ExtendedCapabilities == nil || !application.ExtendedCapabilities.AES {
		t.Skip("card does not announce PSO:ENCIPHER/DECIPHER AES support")
	}

	verifyHardwareAESCredentials(t, ctx, device, password, adminPassword)

	cleanup = func() {
		if err := device.Close(); err != nil {
			t.Errorf("close AES test connection before factory reset: %v", err)
		}

		resetHardwareAESApplication(t, reader, adminPassword)
	}

	input := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	longInput := make([]byte, 320)
	for i := range longInput {
		longInput[i] = byte(i)
	}

	for _, mode := range []struct {
		name     string
		extended bool
	}{
		{name: "short"},
		{name: "extended", extended: true},
	} {
		if mode.extended {
			if err := device.Close(); err != nil {
				t.Fatalf("close short-APDU connection: %v", err)
			}

			connection, err = openpgppcsc.Open(ctx, reader)
			if err != nil {
				t.Fatal(err)
			}

			device = card.New(connection, client.WithExtendedLength())
			verifyHardwareAESCredentials(t, ctx, device, password, adminPassword)
		}

		if !t.Run(mode.name, func(t *testing.T) {
			// FIPS 197 (2001), Appendices C.1 and C.3. A zero CBC ICV makes
			// the first block identical to these AES block-cipher vectors.
			// https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
			for _, keyTest := range []struct {
				name      string
				keyLength int
				wantBlock []byte
			}{
				{
					name: "AES-128", keyLength: 16,
					wantBlock: []byte{0x02, 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a},
				},
				{
					name: "AES-256", keyLength: 32,
					wantBlock: []byte{0x02, 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89},
				},
			} {
				if !t.Run(keyTest.name, func(t *testing.T) {
					key := make([]byte, keyTest.keyLength)
					for i := range key {
						key[i] = byte(i)
					}

					blockCipher, err := aes.NewCipher(key)
					if err != nil {
						t.Fatal(err)
					}

					wantLong := make([]byte, 1+len(longInput))
					wantLong[0] = 0x02
					cipher.NewCBCEncrypter(blockCipher, make([]byte, aes.BlockSize)).CryptBlocks(wantLong[1:], longInput)

					if err := device.PutData(ctx, protocol.AESKeyObject, key, protocol.PW3, nil); err != nil {
						var apdu *baseiso7816.APDUError
						if keyTest.keyLength == 32 && errors.As(err, &apdu) && apdu.StatusWord() == 0x6700 {
							t.Skip("card rejects 32-byte D5 AES key (SW=6700)")
						}

						t.Fatalf("provision AES key: %v", err)
					}

					for _, message := range []struct {
						name  string
						input []byte
						want  []byte
					}{
						{name: "FIPS-block", input: input, want: keyTest.wantBlock},
						{name: "CBC-320", input: longInput, want: wantLong},
					} {
						if !t.Run(message.name, func(t *testing.T) {
							got, err := device.Encipher(ctx, message.input, nil)
							if err != nil {
								t.Fatalf("encipher: %v", err)
							}

							if !bytes.Equal(got, message.want) {
								t.Fatalf("Encipher = %x, want %x", got, message.want)
							}

							plain, err := device.Decipher(ctx, got, nil)
							if err != nil {
								t.Fatalf("decipher: %v", err)
							}

							if !bytes.Equal(plain, message.input) {
								t.Errorf("Decipher = %x, want %x", plain, message.input)
							}
						}) {
							return
						}
					}
				}) {
					return
				}
			}
		}) {
			return
		}
	}
}

func hardwareAESPassword(t testing.TB, variable string) []byte {
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

func verifyHardwareAESCredentials(t testing.TB, ctx context.Context, device *card.Device, password, adminPassword []byte) {
	t.Helper()

	if err := device.Verify(ctx, protocol.PW3, adminPassword); err != nil {
		t.Fatalf("verify configured PW3: %v", err)
	}

	if err := device.Verify(ctx, protocol.PW1, password); err != nil {
		t.Fatalf("verify configured PW1: %v", err)
	}
}

func resetHardwareAESApplication(t *testing.T, reader string, adminPassword []byte) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	connection, err := openpgppcsc.Open(ctx, reader)
	if err != nil {
		t.Errorf("reopen selected reader for factory reset: %v", err)
		return
	}

	device := card.New(connection)
	defer func() {
		if err := device.Close(); err != nil {
			t.Errorf("close factory-reset connection: %v", err)
		}
	}()

	if err := device.Verify(ctx, protocol.PW3, adminPassword); err != nil {
		t.Errorf("verify configured PW3 for factory reset: %v", err)
		return
	}

	if err := device.TerminateDF(ctx, nil); err != nil {
		t.Errorf("terminate test application: %v", err)
		return
	}

	if err := device.Close(); err != nil {
		t.Errorf("close terminated application: %v", err)
	}

	connection, err = openpgppcsc.Open(ctx, reader)
	if err != nil {
		t.Errorf("reopen terminated application: %v", err)
		return
	}

	device = card.New(connection)
	if err := device.ActivateFile(ctx); err != nil {
		t.Errorf("activate test application: %v", err)
		return
	}

	data, err := device.GetData(ctx, protocol.KeyInformationObject)
	if err != nil {
		t.Errorf("read key information after factory reset: %v", err)
		return
	}

	keys, err := protocol.ParseKeyInformation(data)
	if err != nil {
		t.Errorf("parse key information after factory reset: %v", err)
		return
	}

	for i, key := range keys[:3] {
		if key.Reference != protocol.KeyReference(i+1) {
			t.Errorf("key reference %d = %d, want %d", i, key.Reference, i+1)
		}

		if key.Status != 0 {
			t.Errorf("key %d status after factory reset = %d, want absent", key.Reference, key.Status)
		}
	}

	certificates, err := device.GetCardholderCertificates(ctx)
	if err != nil {
		t.Errorf("read certificates after factory reset: %v", err)
		return
	}

	checkHardwareCertificates(t, certificates, protocol.CardholderCertificates{})

	// Use factory PW1 only after our successful factory reset.
	if err := device.Verify(ctx, protocol.PW1, []byte("123456")); err != nil {
		t.Errorf("verify known factory PW1 after reset: %v", err)
		return
	}

	result, err := device.Encipher(ctx, make([]byte, aes.BlockSize), nil)

	var apdu *baseiso7816.APDUError
	if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6a88 || result != nil {
		t.Errorf("Encipher after factory reset = %x, %v; want missing AES key (6a88)", result, err)
	}
}
