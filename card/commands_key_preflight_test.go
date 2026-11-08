package card

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"testing/synctest"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

func TestGenerationPreflightFailureSkipsVerificationAndClearsPassword(t *testing.T) {
	attributes := []byte{99}

	password := []byte("encoded PW3")

	var sequence []byte

	d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
		sequence = append(sequence, command.INS)
		if command.INS != byte(protocol.GetData) || command.P1 != 0 || command.P2 != 0x6e {
			t.Errorf("command = %+v, want only metadata before preflight rejection", command)
		}

		return success(authenticationKeyApplication(attributes)), nil
	}})

	t.Cleanup(func() { _ = d.Close() })

	_, err := d.GenerateAsymmetricKeyPair(t.Context(), protocol.AuthenticationTemplateTag, func(context.Context) ([]byte, error) { return password, nil })

	if !errors.Is(err, protocol.ErrUnsupportedAlgorithm) {
		t.Errorf("error = %v, want %v", err, protocol.ErrUnsupportedAlgorithm)
	}

	if !bytes.Equal(sequence, []byte{0xca}) {
		t.Errorf("sequence = %x, want only GET DATA without VERIFY or key replacement", sequence)
	}

	if !bytes.Equal(password, make([]byte, len(password))) {
		t.Error("preflight rejection did not clear the transferred password")
	}
}

func TestGenerationPreflightVerificationAndReplacementStayTogether(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
		attributes := []byte{0x16, 0x2b, 0x65, 0x70}
		metadataStarted := make(chan struct{})
		continueMetadata := make(chan struct{})
		verifyStarted := make(chan struct{})

		continueVerify := make(chan struct{})
		defer func() {
			for _, wait := range []chan struct{}{continueMetadata, continueVerify} {
				select {
				case <-wait:
				default:
					close(wait)
				}
			}
		}()

		var sequence []byte

		configured := true
		d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
			sequence = append(sequence, command.INS)
			switch protocol.Instruction(command.INS) {
			case protocol.GetData:
				if command.P1 == 0 && command.P2 == byte(protocol.KDFObject) {
					return success(nil), nil
				}

				if command.P1 != 0 || command.P2 != 0x6e {
					t.Errorf("metadata command = %+v", command)
				}

				close(metadataStarted)
				<-continueMetadata

				return success(authenticationKeyApplication(attributes)), nil
			case protocol.Verify:
				if command.P2 != byte(protocol.PW3) {
					t.Errorf("VERIFY reference = %02x, want PW3", command.P2)
				}

				close(verifyStarted)
				<-continueVerify
			case protocol.GenerateAsymmetricKeyPair:
				if !configured {
					t.Error("configuration or selection changed before key replacement")
				}

				return success(append([]byte{0x7f, 0x49, 0x22, 0x86, 0x20}, key.Public().(ed25519.PublicKey)...)), nil
			case protocol.Select:
				configured = false
			default:
				t.Errorf("unexpected command = %+v", command)
			}

			return success(nil), nil
		}})

		t.Cleanup(func() { _ = d.Close() })

		completed := make(chan error, 1)

		go func() {
			source := AuthenticationSource(func(ctx context.Context) ([]byte, error) {
				if _, err := d.GetData(ctx, protocol.KDFObject); err != nil {
					return nil, err
				}

				return []byte("encoded PW3"), nil
			})

			_, err := d.GenerateAsymmetricKeyPair(t.Context(), protocol.AuthenticationTemplateTag, source)
			completed <- err
		}()

		receive(t, metadataStarted, "key attribute read")

		queued := make(chan error, 1)

		go func() {
			queued <- d.Select(t.Context())
		}()

		synctest.Wait()

		if !bytes.Equal(sequence, []byte{0xca, 0xca}) {
			t.Errorf("sequence during metadata = %x, want source and metadata reads", sequence)
		}

		close(continueMetadata)
		receive(t, verifyStarted, "PW3 verification")
		synctest.Wait()

		if !bytes.Equal(sequence, []byte{0xca, 0xca, 0x20}) {
			t.Errorf("sequence during VERIFY = %x, want source read, metadata read, VERIFY", sequence)
		}

		close(continueVerify)

		if err := receive(t, completed, "key replacement"); err != nil {
			t.Fatal(err)
		}

		if err := receive(t, queued, "queued configuration or selection"); err != nil {
			t.Fatal(err)
		}

		want := []byte{0xca, 0xca, 0x20, 0x47, 0xa4}

		if !bytes.Equal(sequence, want) {
			t.Errorf("sequence = %x, want %x", sequence, want)
		}
	})
}
