package card

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"testing"
	"testing/synctest"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport"
)

func TestProtectedWorkflowsVerifyRequiredReferenceBeforeAction(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	template := protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag}
	attributes := protocol.AlgorithmAttributes{Algorithm: protocol.EdDSA, CurveOID: []byte{0x2b, 0x65, 0x70}}
	metadata := bertlv.Append(nil, 0x4f, []byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 6, 0, 0, 0, 1, 0, 0})
	metadata = bertlv.Append(metadata, 0x73, bertlv.Append(nil, 0xc1, []byte{0x16, 0x2b, 0x65, 0x70}))
	metadata = bertlv.Append(nil, 0x6e, metadata)

	tests := []struct {
		name      string
		reference protocol.PasswordReference
		invoke    func(*Device, AuthenticationSource) error
	}{
		{"read private use 3", protocol.PW1, func(d *Device, source AuthenticationSource) error {
			_, err := d.GetDataWithAuthentication(t.Context(), protocol.PrivateUse3Object, protocol.PW1, source)
			return err
		}},
		{"read private use 4", protocol.PW3, func(d *Device, source AuthenticationSource) error {
			_, err := d.GetDataWithAuthentication(t.Context(), protocol.PrivateUse4Object, protocol.PW3, source)
			return err
		}},
		{"signature", protocol.PW1Sign, func(d *Device, source AuthenticationSource) error {
			_, err := d.ComputeDigitalSignature(t.Context(), []byte("input"), source)
			return err
		}},
		{"authentication", protocol.PW1, func(d *Device, source AuthenticationSource) error {
			_, err := d.InternalAuthenticate(t.Context(), []byte("input"), source)
			return err
		}},
		{"authentication with DEC", protocol.PW1, func(d *Device, source AuthenticationSource) error {
			_, err := d.InternalAuthenticateWithKey(t.Context(), protocol.ConfidentialityTemplateTag, []byte("input"), source)
			return err
		}},
		{"decipher", protocol.PW1, func(d *Device, source AuthenticationSource) error {
			_, err := d.Decipher(t.Context(), []byte{0, 1}, source)
			return err
		}},
		{"decipher with AUT", protocol.PW1, func(d *Device, source AuthenticationSource) error {
			_, err := d.DecipherWithKey(t.Context(), protocol.AuthenticationTemplateTag, []byte{0, 1}, source)
			return err
		}},
		{"encipher", protocol.PW1, func(d *Device, source AuthenticationSource) error {
			_, err := d.Encipher(t.Context(), make([]byte, 16), source)
			return err
		}},
		{"generation", protocol.PW3, func(d *Device, source AuthenticationSource) error {
			_, err := d.GenerateAsymmetricKeyPair(t.Context(), template.Tag, source)
			return err
		}},
		{"generation with template", protocol.PW3, func(d *Device, source AuthenticationSource) error {
			_, err := d.GenerateAsymmetricKeyPairWithTemplate(t.Context(), template, attributes, source)
			return err
		}},
		{"import", protocol.PW3, func(d *Device, source AuthenticationSource) error {
			return d.ImportKey(t.Context(), template.Tag, key, source)
		}},
		{"import with template", protocol.PW3, func(d *Device, source AuthenticationSource) error {
			return d.ImportKeyWithTemplate(t.Context(), template, attributes, key, source)
		}},
		{"certificate", protocol.PW3, func(d *Device, source AuthenticationSource) error {
			return d.PutCardholderCertificate(t.Context(), template.Tag, []byte("certificate"), source)
		}},
		{"termination", protocol.PW3, func(d *Device, source AuthenticationSource) error {
			return d.TerminateDF(t.Context(), source)
		}},
		{"reset PW1", protocol.PW3, func(d *Device, source AuthenticationSource) error {
			return d.ResetRetryCounterWithPW3(t.Context(), []byte("replacement"), source)
		}},
		{"object policy", protocol.PW1, func(d *Device, source AuthenticationSource) error {
			return d.PutData(t.Context(), protocol.PrivateUse1Object, []byte("value"), protocol.PW1, source)
		}},
		{"KDF", protocol.PW3, func(d *Device, source AuthenticationSource) error {
			return d.PutKDF(t.Context(), protocol.KDF{}, source)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password := []byte("encoded password")

			var sequence []byte

			d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				sequence = append(sequence, command.INS)
				if command.INS == byte(protocol.GetData) && command.P1 == 0 && command.P2 == 0x6e {
					return success(metadata), nil
				}

				if command.INS == byte(protocol.Verify) {
					if command.P2 != byte(tt.reference) || !bytes.Equal(command.Data, []byte("encoded password")) {
						t.Errorf("VERIFY reference = %02x, password = %q", command.P2, command.Data)
					}

					return iso7816.Response{Status: 0x63c2}, nil
				}

				return success(nil), nil
			}})

			t.Cleanup(func() { _ = d.Close() })

			err := tt.invoke(d, func(context.Context) ([]byte, error) { return password, nil })

			var referenceError *client.ReferenceDataError
			if !errors.As(err, &referenceError) || referenceError.Reference != tt.reference || referenceError.Retries != 2 {
				t.Errorf("error = %v, want reference %02x with 2 retries", err, tt.reference)
			}

			wantSequence := []byte{0x20}
			if tt.name == "generation" || tt.name == "import" {
				wantSequence = []byte{0xca, 0x20}
			}

			if !bytes.Equal(sequence, wantSequence) {
				t.Errorf("sequence = %x, want %x without a protected command after wrong password", sequence, wantSequence)
			}

			if !bytes.Equal(password, make([]byte, len(password))) {
				t.Error("transferred password was not cleared")
			}

			read := make(chan error, 1)

			go func() {
				_, err := d.GetData(t.Context(), protocol.URLObject)
				read <- err
			}()

			if err := receive(t, read, "read after rejected authentication"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCanceledWorkflowWaitClearsTransferredPassword(t *testing.T) {
	d := New(&exchangeTransport{exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
		t.Error("canceled operation transmitted data")
		return success(nil), nil
	}})

	t.Cleanup(func() { _ = d.Close() })

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
		_, err := d.Decipher(ctx, []byte{0, 1}, func(context.Context) ([]byte, error) {
			close(supplied)
			return password, nil
		})
		completed <- err
	}()

	receive(t, supplied, "password source")
	cancel()

	if err := receive(t, completed, "canceled decipher wait"); !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}

	if !bytes.Equal(password, make([]byte, len(password))) {
		t.Error("transferred password was not cleared")
	}
}

func TestWorkflowAuthenticationSourceCanReadDevice(t *testing.T) {
	var sequence []byte

	d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
		sequence = append(sequence, command.INS)
		return success(nil), nil
	}})

	t.Cleanup(func() { _ = d.Close() })

	completed := make(chan error, 1)
	go func() {
		completed <- d.PutData(t.Context(), protocol.URLObject, []byte("url"), protocol.PW3, func(ctx context.Context) ([]byte, error) {
			if _, err := d.GetData(ctx, protocol.KDFObject); err != nil {
				return nil, err
			}

			return []byte("encoded PW3"), nil
		})
	}()

	if err := receive(t, completed, "source reading the device and writing"); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sequence, []byte{0xca, 0x20, 0xda}) {
		t.Errorf("sequence = %x, want GET DATA, VERIFY, PUT DATA", sequence)
	}
}

func TestInvalidatedAuthenticationClosesBeforeReleasingWorkflow(t *testing.T) {
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

		cause := errors.New("connection lost during VERIFY")
		closeErr := errors.New("disconnect failed")

		var (
			calls, closes int
			d             *Device
		)

		d = New(&exchangeTransport{
			exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				calls++

				if command.INS != byte(protocol.Verify) {
					t.Errorf("command after invalidating VERIFY: %02x", command.INS)
					return success(nil), nil
				}

				close(verifyStarted)
				<-continueVerify

				return iso7816.Response{}, &transport.DeviceInvalidatedError{Err: cause}
			},
			close: func() error {
				closes++

				if len(d.mu) != 1 {
					t.Error("workflow released its gate before closing the invalidated transport")
				}

				return closeErr
			},
		})

		t.Cleanup(func() { _ = d.Close() })

		completed := make(chan error, 1)

		go func() {
			_, err := d.Decipher(t.Context(), []byte{0, 1}, func(context.Context) ([]byte, error) {
				return []byte("encoded PW1"), nil
			})
			completed <- err
		}()

		receive(t, verifyStarted, "VERIFY starting")

		read := make(chan error, 1)

		go func() {
			_, err := d.GetData(t.Context(), protocol.URLObject)
			read <- err
		}()

		synctest.Wait()
		close(continueVerify)

		if err := receive(t, completed, "invalidated authentication"); !errors.Is(err, cause) || !errors.Is(err, closeErr) {
			t.Errorf("error = %v, want authentication and close causes", err)
		}

		if err := receive(t, read, "queued read after invalidation"); !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("queued read error = %v, want io.ErrClosedPipe", err)
		}

		if calls != 1 || closes != 1 {
			t.Errorf("calls = %d, closes = %d; want one VERIFY and one close", calls, closes)
		}
	})
}
