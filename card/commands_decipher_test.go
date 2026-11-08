package card

import (
	"bytes"
	"context"
	"testing"
	"testing/synctest"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

func TestDecipherKeepsAuthenticationAndKeySelectionTogether(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		verifyStarted := make(chan struct{})
		continueVerify := make(chan struct{})

		defer func() {
			select {
			case <-continueVerify:
			default:
				close(continueVerify)
			}
		}()

		var (
			sequence []byte
			bindings []byte
		)

		d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
			sequence = append(sequence, command.INS)
			switch protocol.Instruction(command.INS) {
			case protocol.Verify:
				close(verifyStarted)
				<-continueVerify
			case protocol.ManageSecurityEnvironment:
				if command.P2 != byte(protocol.ConfidentialityTemplateTag) || len(command.Data) != 3 {
					t.Errorf("MSE = %+v, want DEC binding", command)
				} else {
					bindings = append(bindings, command.Data[2])
				}
			case protocol.PerformSecurityOperation:
				return success([]byte("plaintext")), nil
			}

			return success(nil), nil
		}})

		t.Cleanup(func() { _ = d.Close() })

		completed := make(chan error, 1)

		go func() {
			plaintext, err := d.DecipherWithKey(t.Context(), protocol.AuthenticationTemplateTag, []byte{0, 1}, func(context.Context) ([]byte, error) {
				return []byte("encoded PW1"), nil
			})
			if err == nil && string(plaintext) != "plaintext" {
				t.Errorf("plaintext = %q", plaintext)
			}

			completed <- err
		}()

		receive(t, verifyStarted, "VERIFY starting")

		read := make(chan error, 1)

		go func() {
			_, err := d.GetData(t.Context(), protocol.URLObject)
			read <- err
		}()

		synctest.Wait()

		if !bytes.Equal(sequence, []byte{0x20}) {
			t.Errorf("command interleaved during VERIFY: %x", sequence)
		}

		close(continueVerify)

		if err := receive(t, completed, "decipher completion"); err != nil {
			t.Fatal(err)
		}

		if err := receive(t, read, "queued read"); err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(sequence, []byte{0x20, 0x22, 0x2a, 0x22, 0xca}) {
			t.Errorf("sequence = %x, want VERIFY, MSE, DECIPHER, MSE, GET DATA", sequence)
		}

		if !bytes.Equal(bindings, []byte{3, 2}) {
			t.Errorf("bindings = %x, want AUT then DEC", bindings)
		}
	})
}
