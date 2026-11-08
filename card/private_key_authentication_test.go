package card

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"errors"
	"slices"
	"testing"
	"testing/synctest"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestSigningKeepsVerificationAndOperationTogether(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		software := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
		verifyStarted := make(chan struct{})
		continueVerify := make(chan struct{})

		defer func() {
			select {
			case <-continueVerify:
			default:
				close(continueVerify)
			}
		}()

		var sequence []byte

		d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
			sequence = append(sequence, command.INS)
			if command.INS == byte(protocol.Verify) {
				if command.P2 != byte(protocol.PW1) {
					t.Errorf("authentication password reference = %02x, want 82", command.P2)
				}

				close(verifyStarted)
				<-continueVerify
			}

			if command.INS == byte(protocol.InternalAuthenticate) {
				return success(ed25519.Sign(software, command.Data)), nil
			}

			return success(nil), nil
		}})

		t.Cleanup(func() { _ = d.Close() })

		key := &PrivateKey{device: d, templateTag: protocol.AuthenticationTemplateTag, publicKey: software.Public()}
		signed := make(chan error, 1)

		go func() {
			_, err := key.Sign(t.Context(), []byte("message"), crypto.Hash(0), func(context.Context) ([]byte, error) {
				return []byte("encoded password"), nil
			})
			signed <- err
		}()

		receive(t, verifyStarted, "VERIFY starting")

		read := make(chan error, 1)

		go func() {
			_, err := d.GetData(t.Context(), protocol.URLObject)
			read <- err
		}()

		synctest.Wait()

		if !bytes.Equal(sequence, []byte{0x20}) {
			t.Fatalf("command interleaved during VERIFY: %x", sequence)
		}

		close(continueVerify)

		if err := receive(t, signed, "signature completion"); err != nil {
			t.Fatal(err)
		}

		if err := receive(t, read, "queued read"); err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(sequence, []byte{0x20, 0x88, 0xca}) {
			t.Errorf("sequence = %x, want VERIFY, INTERNAL AUTHENTICATE, GET DATA", sequence)
		}
	})
}

func TestAuthenticationSourceCanReadDevice(t *testing.T) {
	software := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

	var sequence []byte

	d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
		sequence = append(sequence, command.INS)
		if command.INS == byte(protocol.PerformSecurityOperation) {
			return success(ed25519.Sign(software, command.Data)), nil
		}

		return success(nil), nil
	}})

	t.Cleanup(func() { _ = d.Close() })

	key := &PrivateKey{device: d, templateTag: protocol.DigitalSignatureTemplateTag, publicKey: software.Public()}
	completed := make(chan error, 1)

	go func() {
		_, err := key.Sign(t.Context(), []byte("message"), crypto.Hash(0), func(ctx context.Context) ([]byte, error) {
			_, err := d.GetData(ctx, protocol.KDFObject)
			return []byte("encoded password"), err
		})
		completed <- err
	}()

	if err := receive(t, completed, "source reading the device and signing"); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sequence, []byte{0xca, 0x20, 0x2a}) {
		t.Errorf("sequence = %x, want GET DATA, VERIFY, SIGN", sequence)
	}
}

func TestCanceledSigningWaitClearsTransferredPassword(t *testing.T) {
	software := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	d := New(&exchangeTransport{exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
		t.Error("canceled operation transmitted data")
		return success(nil), nil
	}})

	t.Cleanup(func() { _ = d.Close() })

	key := &PrivateKey{device: d, templateTag: protocol.DigitalSignatureTemplateTag, publicKey: software.Public()}
	if err := d.lock(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer d.unlock()

	password := []byte("encoded password")
	supplied := make(chan struct{})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	completed := make(chan error, 1)

	go func() {
		_, err := key.Sign(ctx, []byte("message"), crypto.Hash(0), func(context.Context) ([]byte, error) {
			close(supplied)
			return password, nil
		})
		completed <- err
	}()

	receive(t, supplied, "password source")
	cancel()

	if err := receive(t, completed, "canceled signing wait"); !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}

	if !bytes.Equal(password, make([]byte, len(password))) {
		t.Error("transferred password was not cleared")
	}
}

func TestWrongPasswordStopsSigningAndClearsBuffer(t *testing.T) {
	software := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	password := []byte("encoded password")

	var calls int

	d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
		calls++

		if command.INS != byte(protocol.Verify) {
			t.Errorf("command after password failure: %02x", command.INS)
		}

		return iso7816.Response{Status: 0x63c2}, nil
	}})

	t.Cleanup(func() { _ = d.Close() })

	key := &PrivateKey{device: d, templateTag: protocol.DigitalSignatureTemplateTag, publicKey: software.Public()}

	signature, err := key.Sign(t.Context(), []byte("message"), crypto.Hash(0), func(context.Context) ([]byte, error) {
		return password, nil
	})

	var referenceError *client.ReferenceDataError
	if !errors.As(err, &referenceError) || referenceError.Reference != protocol.PW1Sign || referenceError.Retries != 2 {
		t.Errorf("error = %v, want PW1Sign with 2 retries", err)
	}

	if signature != nil || calls != 1 {
		t.Errorf("signature = %x, calls = %d", signature, calls)
	}

	if !bytes.Equal(password, make([]byte, len(password))) {
		t.Error("password was not cleared")
	}
}

func TestSourceFailurePreservesCallerOwnership(t *testing.T) {
	software := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	password := []byte("encoded password")
	want := slices.Clone(password)
	sourceErr := errors.New("password source failed")
	d := New(&exchangeTransport{exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
		t.Error("operation transmitted after source failure")
		return success(nil), nil
	}})

	t.Cleanup(func() { _ = d.Close() })

	key := &PrivateKey{device: d, templateTag: protocol.DigitalSignatureTemplateTag, publicKey: software.Public()}

	_, err := key.Sign(t.Context(), []byte("message"), crypto.Hash(0), func(context.Context) ([]byte, error) {
		return password, sourceErr
	})
	if !errors.Is(err, sourceErr) {
		t.Errorf("error = %v, want source failure", err)
	}

	if !bytes.Equal(password, want) {
		t.Error("source-owned buffer was changed")
	}
}
