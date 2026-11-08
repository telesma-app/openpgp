package pcsc_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/openpgp/card"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
	openpgpiso7816 "github.com/telesma-app/openpgp/transport/iso7816"
	nativepcsc "github.com/telesma-app/pcsc"
)

// TestHardwareReadControlReferenceTemplate compares an existing Yubico attestation
// key and certificate using extended CRTs in short and extended APDUs. It neither
// evaluates chain trust nor submits PINs, writes data or resets the card.
func TestHardwareReadControlReferenceTemplate(t *testing.T) {
	if os.Getenv("OPENPGP_TEST") != "1" {
		t.Skip("set OPENPGP_TEST=1 to read an existing attestation key")
	}

	reader := os.Getenv("OPENPGP_TEST_READER")
	if reader == "" {
		t.Fatal("OPENPGP_TEST_READER must name one exact reader")
	}

	for _, test := range []struct {
		name    string
		options []client.Option
	}{
		{name: "short"},
		{name: "extended", options: []client.Option{client.WithExtendedLength()}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			native, err := nativepcsc.Open(reader,
				nativepcsc.WithShareMode(nativepcsc.ShareModeExclusive),
				nativepcsc.WithDisconnectDisposition(nativepcsc.DispositionLeaveCard),
			)
			if err != nil {
				t.Fatal(err)
			}

			closeConnection := native.Close

			t.Cleanup(func() {
				if err := closeConnection(); err != nil {
					t.Error(err)
				}
			})

			connection, err := openpgpiso7816.Open(ctx, native)
			if err != nil {
				t.Fatal(err)
			}

			device := card.New(connection, test.options...)
			closeConnection = device.Close

			application, err := device.GetApplicationRelatedData(ctx)
			if err != nil {
				t.Fatal(err)
			}

			var attestationKeyPresent bool

			for _, key := range application.KeyInformation {
				if key.Reference == protocol.AttestationKeyReference && key.Status != 0 {
					attestationKeyPresent = true
					break
				}
			}

			if !attestationKeyPresent {
				t.Skip("application does not report an existing key 81")
			}

			// Yubico ATT: DA attributes in discretionary metadata, FC certificate,
			// B6 03 84 01 81 CRT. https://developers.yubico.com/PGP/Attestation.html
			attributes := readYubicoAttestationAttributes(t, application.Raw)

			data, err := device.GetData(ctx, protocol.Object(0xfc))
			if err != nil {
				t.Fatal(err)
			}

			certificate, err := x509.ParseCertificate(data)
			if err != nil {
				t.Fatal(err)
			}

			key, err := device.ReadPublicKeyWithTemplate(ctx, protocol.ControlReferenceTemplate{
				Tag:          protocol.DigitalSignatureTemplateTag,
				KeyReference: protocol.AttestationKeyReference,
			}, attributes)
			if err != nil {
				t.Fatal(err)
			}

			public := key.(interface{ Equal(crypto.PublicKey) bool })
			if !public.Equal(certificate.PublicKey) {
				t.Fatalf("key 81 (%T) differs from the attestation certificate public key", key)
			}

			t.Logf("key 81 (%T) matches the attestation certificate public key", key)
		})
	}
}

func readYubicoAttestationAttributes(t testing.TB, data []byte) protocol.AlgorithmAttributes {
	t.Helper()

	if len(data) != 0 && data[0] == 0x6e {
		var err error

		data, err = protocol.ParseObject(data, 0x6e)
		if err != nil {
			t.Fatalf("application metadata template: %v", err)
		}
	}

	for len(data) != 0 {
		tag, discretionary, rest, err := bertlv.Parse(data)
		if err != nil {
			t.Fatalf("application metadata: %v", err)
		}

		data = rest

		if tag != 0x73 {
			continue
		}

		for len(discretionary) != 0 {
			tag, value, rest, err := bertlv.Parse(discretionary)
			if err != nil {
				t.Fatalf("application discretionary metadata: %v", err)
			}

			discretionary = rest

			if tag == 0xda {
				attributes, err := protocol.ParseAlgorithmAttributes(value)
				if err != nil {
					t.Fatalf("Yubico attestation algorithm attributes: %v", err)
				}

				return attributes
			}
		}
	}

	t.Fatal("application metadata has no Yubico attestation algorithm attributes")

	return protocol.AlgorithmAttributes{}
}
