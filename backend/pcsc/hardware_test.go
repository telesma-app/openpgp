package pcsc_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/telesma-app/iso7816"
	openpgppcsc "github.com/telesma-app/openpgp/backend/pcsc"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

// TestHardwareRead reads metadata and public keys without a PIN or card writes.
func TestHardwareRead(t *testing.T) {
	if os.Getenv("OPENPGP_TEST") != "1" {
		t.Skip("set OPENPGP_TEST=1 to inspect connected OpenPGP cards")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	wantedReader := os.Getenv("OPENPGP_TEST_READER")

	var selected int

	for reader, err := range openpgppcsc.Devices(ctx) {
		if err != nil {
			t.Fatal(err)
		}

		if wantedReader != "" && reader.Name != wantedReader {
			continue
		}

		t.Run(reader.Name, func(t *testing.T) {
			device, err := openpgppcsc.Open(ctx, reader.Name)
			if err != nil {
				var apdu *iso7816.APDUError
				if errors.As(err, &apdu) && apdu.StatusWord() == 0x6a82 {
					t.Skip("OpenPGP application absent")
				}

				t.Fatal(err)
			}

			selected++

			t.Cleanup(func() {
				if err := device.Close(); err != nil {
					t.Error(err)
				}
			})

			commands := client.NewClient(device)

			aid, err := commands.GetApplicationIdentifier(ctx)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("OpenPGP version %02x.%02x, manufacturer %04x", aid.VersionMajor, aid.VersionMinor, aid.Manufacturer)

			application, err := commands.GetApplicationRelatedData(ctx)
			if err != nil {
				t.Errorf("GET DATA 6E: %v", err)
			} else {
				if application.AID != aid {
					t.Errorf("GET DATA 6E AID = %s, want %s", application.AID, aid)
				}

				t.Logf("application metadata: %d bytes, capabilities present: %t", len(application.Raw), application.ExtendedCapabilities != nil)
			}

			if _, err := commands.GetCardholderRelatedData(ctx); err != nil {
				t.Errorf("GET DATA 65: %v", err)
			}

			if _, err := commands.GetSecuritySupportTemplate(ctx); err != nil {
				t.Errorf("GET DATA 7A: %v", err)
			}

			keyInformation, err := commands.GetData(ctx, protocol.KeyInformationObject)
			if err != nil {
				t.Fatal(err)
			}

			keyStatus := make(map[byte]byte)

			if len(keyInformation)%2 == 0 {
				for i := 0; i < len(keyInformation); i += 2 {
					keyStatus[keyInformation[i]] = keyInformation[i+1]
				}
			}

			t.Logf("key information: %x", keyInformation)

			for index, key := range []protocol.ControlReferenceTemplateTag{protocol.DigitalSignatureTemplateTag, protocol.ConfidentialityTemplateTag, protocol.AuthenticationTemplateTag} {
				response, err := device.Exchange(ctx, iso7816.Command{
					INS: 0x47, P1: 0x81, Data: []byte{byte(key), 0x00}, Le: 256,
				})
				if err != nil {
					t.Fatal(err)
				}

				status, known := keyStatus[byte(index+1)]
				if err := response.APDUError(); err != nil {
					if known && status == 0 {
						t.Logf("empty public key slot %02x: SW=%s", byte(key), response.Status)
						continue
					}

					t.Errorf("READ PUBLIC KEY %02x: %v", byte(key), err)

					continue
				}

				publicKey, err := commands.ReadPublicKey(ctx, key)
				if err != nil {
					t.Errorf("parse public key %02x: %v", byte(key), err)
					continue
				}

				t.Logf("public key %02x: %T", byte(key), publicKey)
			}
		})
	}

	if selected == 0 {
		t.Fatal("no OpenPGP card selected")
	}
}
