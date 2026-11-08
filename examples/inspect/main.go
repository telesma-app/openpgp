// Command inspect reads connected OpenPGP cards without submitting passwords
// or modifying their contents. Both USB CCID tokens and PC/SC NFC readers work.
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/telesma-app/iso7816"
	openpgppcsc "github.com/telesma-app/openpgp/backend/pcsc"
	"github.com/telesma-app/openpgp/card"
	"github.com/telesma-app/openpgp/protocol"
)

func main() {
	reader := flag.String("reader", "", "exact PC/SC reader name; default: inspect all inserted cards")
	timeout := flag.Duration("timeout", 30*time.Second, "timeout for the complete inspection")

	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	if err := run(ctx, *reader); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, selectedReader string) error {
	if selectedReader != "" {
		_, err := inspect(ctx, selectedReader)
		return err
	}

	var (
		result    error
		inspected int
	)

	for reader, err := range openpgppcsc.Devices(ctx) {
		if err != nil {
			return errors.Join(result, err)
		}

		fmt.Printf("reader: %q, ATR: %x\n", reader.Name, reader.ATR)

		found, err := inspect(ctx, reader.Name)
		if found {
			inspected++
		}

		var apdu *iso7816.APDUError
		if !found && errors.As(err, &apdu) && apdu.StatusWord() == 0x6a82 {
			fmt.Println("OpenPGP application absent")
			continue
		}

		if err != nil {
			result = errors.Join(result, fmt.Errorf("reader %q: %w", reader.Name, err))
			continue
		}
	}

	if inspected == 0 {
		result = errors.Join(result, errors.New("no OpenPGP card inspected"))
	}

	return result
}

func inspect(ctx context.Context, reader string) (found bool, err error) {
	connection, err := openpgppcsc.Open(ctx, reader)
	if err != nil {
		return false, err
	}

	device := card.New(connection)
	defer func() { err = errors.Join(err, device.Close()) }()

	return true, inspectCard(ctx, device)
}

func inspectCard(ctx context.Context, device *card.Device) error {
	application, err := device.GetApplicationRelatedData(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("OpenPGP %02x.%02x, manufacturer %04x, AID %s\n",
		application.AID.VersionMajor, application.AID.VersionMinor,
		application.AID.Manufacturer, application.AID)

	if caps := application.ExtendedCapabilities; caps != nil {
		fmt.Printf("key import: %t, changeable algorithms: %t, KDF: %t, secure messaging: %t\n",
			caps.KeyImport, caps.AlgorithmAttributesChangeable, caps.KDF, caps.SecureMessaging)
	}

	passwords, err := device.GetPWStatusBytes(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("retries: PW1=%d, resetting code=%d, PW3=%d; reusable signing verification: %t\n",
		passwords.PW1Retries, passwords.ResettingCodeRetries, passwords.PW3Retries,
		passwords.PW1ValidForMultipleSignatures)

	counter, err := device.GetSecuritySupportTemplate(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("signature counter: %d\n", counter.DigitalSignatureCounter)

	for _, slot := range []struct {
		name         string
		tag          protocol.ControlReferenceTemplateTag
		keyReference protocol.KeyReference
	}{
		{name: "SIG", tag: protocol.DigitalSignatureTemplateTag, keyReference: protocol.SignatureKeyReference},
		{name: "DEC", tag: protocol.ConfidentialityTemplateTag, keyReference: protocol.DecryptionKeyReference},
		{name: "AUT", tag: protocol.AuthenticationTemplateTag, keyReference: protocol.AuthenticationKeyReference},
	} {
		var empty bool

		for _, info := range application.KeyInformation {
			if info.Reference == slot.keyReference {
				empty = info.Status == protocol.KeyStatusNotPresent
				break
			}
		}

		if empty {
			fmt.Printf("%s public key: empty\n", slot.name)
			continue
		}

		public, err := device.ReadPublicKey(ctx, slot.tag)
		if err != nil {
			var apdu *iso7816.APDUError
			if errors.As(err, &apdu) && (apdu.StatusWord() == 0x6a88 || apdu.StatusWord() == 0x6a82) {
				fmt.Printf("%s public key: absent (SW=%s)\n", slot.name, apdu.StatusWord())
				continue
			}

			if errors.Is(err, protocol.ErrUnsupportedAlgorithm) {
				fmt.Printf("%s public key: %v\n", slot.name, err)
				continue
			}

			return err
		}

		switch public := public.(type) {
		case *rsa.PublicKey:
			fmt.Printf("%s public key: RSA-%d, exponent %d\n", slot.name, public.N.BitLen(), public.E)
		case *ecdsa.PublicKey:
			fmt.Printf("%s public key: ECDSA %s\n", slot.name, public.Curve.Params().Name)
		case *ecdh.PublicKey:
			fmt.Printf("%s public key: ECDH %v\n", slot.name, public.Curve())
		case protocol.ECDHPublicKey:
			fmt.Printf("%s public key: ECDH curve OID %x\n", slot.name, public.CurveOID)
		case ed25519.PublicKey:
			fmt.Printf("%s public key: Ed25519\n", slot.name)
		default:
			fmt.Printf("%s public key: %T\n", slot.name, public)
		}
	}

	fmt.Println()

	return nil
}
