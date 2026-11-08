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

func TestImportTemplateMismatchSkipsAuthentication(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	attributes := protocol.AlgorithmAttributes{
		Algorithm: protocol.ECDSA,
		CurveOID:  []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
	}
	d := New(&exchangeTransport{exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
		t.Error("mismatched import transmitted data")
		return success(nil), nil
	}})

	t.Cleanup(func() { _ = d.Close() })

	err := d.ImportKeyWithTemplate(t.Context(), protocol.ControlReferenceTemplate{
		Tag: protocol.AuthenticationTemplateTag,
	}, attributes, key, func(context.Context) ([]byte, error) {
		t.Error("mismatched import requested authentication")
		return []byte("encoded PW3"), nil
	})

	if !errors.Is(err, protocol.ErrKeyMismatch) {
		t.Errorf("error = %v, want protocol.ErrKeyMismatch", err)
	}
}

func TestKeyPreflightFailureSkipsVerificationAndClearsPassword(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

	for _, test := range []struct {
		name       string
		attributes []byte
		want       error
		invoke     func(*Device, AuthenticationSource) error
	}{
		{
			name: "import key mismatch", attributes: []byte{0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
			want: protocol.ErrKeyMismatch,
			invoke: func(d *Device, source AuthenticationSource) error {
				return d.ImportKey(t.Context(), protocol.AuthenticationTemplateTag, key, source)
			},
		},
		{
			name: "unsupported generation", attributes: []byte{99}, want: protocol.ErrUnsupportedAlgorithm,
			invoke: func(d *Device, source AuthenticationSource) error {
				_, err := d.GenerateAsymmetricKeyPair(t.Context(), protocol.AuthenticationTemplateTag, source)
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			password := []byte("encoded PW3")

			var sequence []byte

			d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				sequence = append(sequence, command.INS)
				if command.INS != byte(protocol.GetData) || command.P1 != 0 || command.P2 != 0x6e {
					t.Errorf("command = %+v, want only metadata before preflight rejection", command)
				}

				return success(importTestApplication(test.attributes)), nil
			}})

			t.Cleanup(func() { _ = d.Close() })

			err := test.invoke(d, func(context.Context) ([]byte, error) { return password, nil })

			if !errors.Is(err, test.want) {
				t.Errorf("error = %v, want %v", err, test.want)
			}

			if !bytes.Equal(sequence, []byte{0xca}) {
				t.Errorf("sequence = %x, want only GET DATA without VERIFY or key replacement", sequence)
			}

			if !bytes.Equal(password, make([]byte, len(password))) {
				t.Error("preflight rejection did not clear the transferred password")
			}
		})
	}
}

func TestKeyPreflightVerificationAndReplacementStayTogether(t *testing.T) {
	for _, operation := range []string{"import", "generate"} {
		t.Run(operation, func(t *testing.T) {
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

						return success(importTestApplication(attributes)), nil
					case protocol.Verify:
						if command.P2 != byte(protocol.PW3) {
							t.Errorf("VERIFY reference = %02x, want PW3", command.P2)
						}

						close(verifyStarted)
						<-continueVerify
					case protocol.PutDataOdd, protocol.GenerateAsymmetricKeyPair:
						if !configured {
							t.Error("configuration or selection changed before key replacement")
						}

						if operation == "generate" {
							return success(append([]byte{0x7f, 0x49, 0x22, 0x86, 0x20}, key.Public().(ed25519.PublicKey)...)), nil
						}
					case protocol.PutData, protocol.Select:
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
					if operation == "import" {
						completed <- d.ImportKey(t.Context(), protocol.AuthenticationTemplateTag, key, source)
					} else {
						_, err := d.GenerateAsymmetricKeyPair(t.Context(), protocol.AuthenticationTemplateTag, source)
						completed <- err
					}
				}()

				receive(t, metadataStarted, "key attribute read")

				queued := make(chan error, 1)

				go func() {
					if operation == "import" {
						queued <- d.PutData(t.Context(), protocol.AuthenticationAlgorithmAttributesObject, []byte{99}, protocol.PW3, nil)
					} else {
						queued <- d.Select(t.Context())
					}
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

				want := []byte{0xca, 0xca, 0x20, 0xdb, 0xda}
				if operation == "generate" {
					want = []byte{0xca, 0xca, 0x20, 0x47, 0xa4}
				}

				if !bytes.Equal(sequence, want) {
					t.Errorf("sequence = %x, want %x", sequence, want)
				}
			})
		})
	}
}

func TestRejectedKeyImportClearsPreparedData(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	password := []byte("encoded PW3")
	attributes := protocol.AlgorithmAttributes{Algorithm: protocol.EdDSA, CurveOID: []byte{0x2b, 0x65, 0x70}}

	var payload, sequence []byte

	d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
		sequence = append(sequence, command.INS)
		if command.INS == byte(protocol.PutDataOdd) {
			payload = command.Data
			if !bytes.Contains(payload, bytes.Repeat([]byte{0x42}, ed25519.SeedSize)) {
				t.Error("import payload does not contain the prepared seed")
			}

			return iso7816.Response{Status: 0x6982}, nil
		}

		return success(nil), nil
	}})

	t.Cleanup(func() { _ = d.Close() })

	err := d.ImportKeyWithTemplate(t.Context(), protocol.ControlReferenceTemplate{
		Tag: protocol.AuthenticationTemplateTag,
	}, attributes, key, func(context.Context) ([]byte, error) { return password, nil })

	var apdu *iso7816.APDUError
	if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6982 {
		t.Errorf("error = %v, want APDU status 6982", err)
	}

	if !bytes.Equal(sequence, []byte{0x20, 0xdb}) {
		t.Errorf("sequence = %x, want VERIFY, IMPORT", sequence)
	}

	if len(payload) == 0 || !bytes.Equal(payload, make([]byte, len(payload))) {
		t.Error("rejected import did not clear the prepared payload")
	}

	if !bytes.Equal(password, make([]byte, len(password))) {
		t.Error("rejected import did not clear the transferred password")
	}
}
