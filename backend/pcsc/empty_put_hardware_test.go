package pcsc_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/card"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
	openpgpiso7816 "github.com/telesma-app/openpgp/transport/iso7816"
	nativepcsc "github.com/telesma-app/pcsc"
)

// TestHardwareEmptyPutData compares case 1/2S/2E empty PUT DATA in short and
// extended certificate workflows, checking that only the target is cleared.
// Certificates are restored after each workflow; keys and passwords are unchanged.
// PW3 is supplied explicitly, including any KDF.
func TestHardwareEmptyPutData(t *testing.T) {
	if os.Getenv("OPENPGP_TEST_WRITE") != "1" {
		t.Skip("set OPENPGP_TEST_WRITE=1 to compare empty PUT DATA encodings on a selected test card")
	}

	reader := os.Getenv("OPENPGP_TEST_READER")
	if reader == "" {
		t.Fatal("OPENPGP_TEST_READER must name one exact reader")
	}

	encodedPassword := os.Getenv("OPENPGP_TEST_PW3_HEX")
	if encodedPassword == "" {
		t.Fatal("OPENPGP_TEST_PW3_HEX must contain the encoded PW3 as hexadecimal bytes")
	}

	password, err := hex.DecodeString(encodedPassword)
	if err != nil {
		t.Fatal("OPENPGP_TEST_PW3_HEX must contain valid hexadecimal bytes")
	}

	t.Cleanup(func() { clear(password) })

	fixtures := protocol.CardholderCertificates{
		Authentication: newHardwareCertificate(t, 1, "empty PUT AUT"),
		Decryption:     newHardwareCertificate(t, 2, "empty PUT DEC"),
		Signature:      newHardwareCertificate(t, 3, "empty PUT SIG"),
	}
	slots := []struct {
		name string
		key  protocol.ControlReferenceTemplateTag
		data []byte
	}{
		{name: "AUT", key: protocol.AuthenticationTemplateTag, data: fixtures.Authentication},
		{name: "DEC", key: protocol.ConfidentialityTemplateTag, data: fixtures.Decryption},
		{name: "SIG", key: protocol.DigitalSignatureTemplateTag, data: fixtures.Signature},
	}

	var authenticationFailed bool

	for _, mode := range []struct {
		name    string
		options []client.Option
	}{
		{name: "short"},
		{name: "extended", options: []client.Option{client.WithExtendedLength()}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()

			native, err := nativepcsc.Open(reader,
				nativepcsc.WithShareMode(nativepcsc.ShareModeExclusive),
				nativepcsc.WithDisconnectDisposition(nativepcsc.DispositionResetCard),
			)
			if err != nil {
				t.Fatal(err)
			}

			t.Cleanup(func() {
				if err := native.Close(); err != nil {
					t.Errorf("close native card: %v", err)
				}
			})

			status, err := native.Status()
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("reader=%q PC/SC protocol=%d ATR=%x", reader, status.Protocol, status.ATR)

			trace := &emptyPutHardwareCard{Card: native}

			connection, err := openpgpiso7816.Open(ctx, trace)
			if err != nil {
				t.Fatal(err)
			}

			device := card.New(connection, mode.options...)
			cleanup := func() {
				if err := device.Close(); err != nil {
					t.Errorf("close empty PUT test connection: %v", err)
				}
			}

			t.Cleanup(func() { cleanup() })

			original, err := device.GetCardholderCertificates(ctx)
			if err != nil {
				t.Fatalf("snapshot certificates: %v", err)
			}

			t.Logf("original AUT length=%d SHA256=%x", len(original.Authentication), sha256.Sum256(original.Authentication))
			t.Logf("original DEC length=%d SHA256=%x", len(original.Decryption), sha256.Sum256(original.Decryption))
			t.Logf("original SIG length=%d SHA256=%x", len(original.Signature), sha256.Sum256(original.Signature))

			if err := device.Verify(ctx, protocol.PW3, password); err != nil {
				authenticationFailed = true

				t.Fatalf("verify configured PW3: %v", err)
			}

			cleanup = func() {
				if err := device.Close(); err != nil {
					t.Errorf("close empty PUT test connection before restoration: %v", err)
				}

				restoreHardwareCertificates(t, reader, password, original)
			}

			for _, candidate := range []struct {
				name     string
				encoding iso7816.Encoding
				le       uint32
				apdu     []byte
			}{
				{name: "case1", encoding: iso7816.EncodingShort, apdu: []byte{0, 0xda, 0x7f, 0x21}},
				{name: "case2-short", encoding: iso7816.EncodingShort, le: 256, apdu: []byte{0, 0xda, 0x7f, 0x21, 0}},
				{name: "case2-extended", encoding: iso7816.EncodingExtended, le: 65536, apdu: []byte{0, 0xda, 0x7f, 0x21, 0, 0, 0}},
			} {
				t.Run(candidate.name, func(t *testing.T) {
					for _, slot := range slots {
						t.Run(slot.name, func(t *testing.T) {
							for _, fixture := range slots {
								if err := device.PutCardholderCertificate(ctx, fixture.key, fixture.data, nil); err != nil {
									t.Fatalf("write %s fixture: %v", fixture.name, err)
								}
							}

							before, err := device.GetCardholderCertificate(ctx, slot.key)
							if err != nil {
								t.Fatalf("select and read fixture: %v", err)
							}

							if !bytes.Equal(before, slot.data) {
								t.Fatal("selected certificate differs from the written fixture")
							}

							trace.t, trace.expected, trace.exchanges = t, candidate.apdu, 0
							response, err := device.Exchange(ctx, iso7816.Command{
								INS: 0xda, P1: 0x7f, P2: 0x21,
								Le: candidate.le, Encoding: candidate.encoding,
							})
							trace.expected = nil

							if err != nil {
								t.Fatalf("send empty PUT: %v", err)
							}

							if trace.exchanges != 1 {
								t.Errorf("empty PUT exchanges=%d, want 1", trace.exchanges)
							}

							if err := response.APDUError(); err != nil {
								t.Errorf("empty PUT status: %v", err)
							}

							if len(response.Data) != 0 {
								t.Errorf("unexpected empty PUT response data: %x", response.Data)
							}

							after, err := device.GetCardholderCertificate(ctx, slot.key)
							if err != nil {
								t.Fatalf("read cleared certificate: %v", err)
							}

							t.Logf("readback length=%d prefix=%x", len(after), after[:min(len(after), 16)])

							if len(after) != 0 {
								t.Error("empty PUT did not clear the certificate")
							}

							want := fixtures

							switch slot.key {
							case protocol.AuthenticationTemplateTag:
								want.Authentication = nil
							case protocol.ConfidentialityTemplateTag:
								want.Decryption = nil
							case protocol.DigitalSignatureTemplateTag:
								want.Signature = nil
							}

							got, err := device.GetCardholderCertificates(ctx)
							if err != nil {
								t.Fatalf("traverse certificates after empty PUT: %v", err)
							}

							checkHardwareCertificates(t, got, want)
						})
					}
				})
			}
		})

		if authenticationFailed {
			return
		}
	}
}

// Capture only the candidate exchange, so VERIFY data never enters the log.
type emptyPutHardwareCard struct {
	*nativepcsc.Card
	t         *testing.T
	expected  []byte
	exchanges int
}

func (c *emptyPutHardwareCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	if c.expected == nil {
		return c.Card.Transmit(ctx, apdu)
	}

	c.exchanges++
	if !bytes.Equal(apdu, c.expected) {
		c.t.Errorf("transmitted APDU=%x, want %x", apdu, c.expected)
	}

	response, err := c.Card.Transmit(ctx, apdu)
	c.t.Logf("transmitted APDU=%x response=%x error=%v", apdu, response, err)

	return response, err
}
