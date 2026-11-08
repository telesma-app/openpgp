package card

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"io"
	"testing"
	"testing/synctest"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport"
)

func TestImportKeepsAttributesAndReplacementTogether(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		key := importTestKey(t)
		attributes := []byte{0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
		replacement := []byte{0x13, 0x2b, 0x81, 0x04, 0x00, 0x22}
		currentAttributes := attributes
		attributesStarted := make(chan struct{})
		continueAttributes := make(chan struct{})

		defer func() {
			select {
			case <-continueAttributes:
			default:
				close(continueAttributes)
			}
		}()

		var instructions []byte

		d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
			instructions = append(instructions, command.INS)
			switch command.INS {
			case byte(protocol.GetData):
				if command.P1 != 0 || command.P2 != 0x6e {
					t.Errorf("attribute read object = %02x%02x, want 006e", command.P1, command.P2)
				}

				close(attributesStarted)
				<-continueAttributes

				return success(importTestApplication(currentAttributes)), nil
			case byte(protocol.PutDataOdd):
				if command.P1 != 0x3f || command.P2 != 0xff || command.Le != 0 {
					t.Errorf("import parameters = %02x%02x, Le=%d; want 3fff without Le", command.P1, command.P2, command.Le)
				}

				if !bytes.Equal(currentAttributes, attributes) {
					t.Error("card attributes changed between their read and key replacement")
					return iso7816.Response{Status: 0x6a80}, nil
				}
			case byte(protocol.PutData):
				if command.P1 != 0 || command.P2 != 0xc3 {
					t.Errorf("configuration object = %02x%02x, want 00c3", command.P1, command.P2)
				}

				currentAttributes = command.Data
			default:
				t.Errorf("unexpected instruction %02x", command.INS)
			}

			return success(nil), nil
		}})

		t.Cleanup(func() {
			if err := d.Close(); err != nil {
				t.Error(err)
			}
		})

		imported := make(chan error, 1)
		go func() {
			imported <- d.ImportKey(t.Context(), protocol.AuthenticationTemplateTag, key, nil)
		}()

		receive(t, attributesStarted, "import attribute read")

		configured := make(chan error, 1)
		go func() {
			configured <- d.PutData(t.Context(), protocol.AuthenticationAlgorithmAttributesObject, replacement, protocol.PW3, nil)
		}()

		synctest.Wait()

		if !bytes.Equal(instructions, []byte{0xca}) {
			t.Fatalf("instructions during attribute read = %x, want only GET DATA", instructions)
		}

		close(continueAttributes)

		if err := receive(t, imported, "key import"); err != nil {
			t.Fatal(err)
		}

		if err := receive(t, configured, "queued algorithm configuration"); err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(instructions, []byte{0xca, 0xdb, 0xda}) {
			t.Errorf("instructions = %x, want GET DATA, IMPORT, PUT DATA", instructions)
		}

		if !bytes.Equal(currentAttributes, replacement) {
			t.Error("queued algorithm configuration was not applied")
		}
	})
}

func TestInvalidatedImportClosesDevice(t *testing.T) {
	key := importTestKey(t)
	attributes := protocol.AlgorithmAttributes{
		Algorithm: protocol.ECDSA, CurveOID: []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
	}
	metadata := importTestApplication([]byte{0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07})

	for _, test := range []struct {
		name     string
		template bool
		phase    int
		want     []byte
	}{
		{name: "standard attribute read", phase: 1, want: []byte{0xca}},
		{name: "standard import", phase: 2, want: []byte{0xca, 0xdb}},
		{name: "explicit template import", template: true, phase: 1, want: []byte{0xdb}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cause := errors.New("card disconnected")
			closeErr := errors.New("card close failed")

			var (
				instructions []byte
				closes       int
			)

			d := New(&exchangeTransport{
				exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
					instructions = append(instructions, command.INS)
					if command.INS == byte(protocol.PutDataOdd) {
						if command.P1 != 0x3f || command.P2 != 0xff || command.Le != 0 {
							t.Errorf("import parameters = %02x%02x, Le=%d", command.P1, command.P2, command.Le)
						}

						body, err := protocol.ParseObject(command.Data, 0x4d)
						if err != nil {
							t.Error(err)
						}

						crt := []byte{0xa4, 0}
						if test.template {
							crt = []byte{0xa4, 3, 0x84, 1, 3}
						}

						if !bytes.HasPrefix(body, crt) {
							t.Error("import did not preserve the requested AUT template")
						}
					}

					if len(instructions) == test.phase {
						return iso7816.Response{}, &transport.DeviceInvalidatedError{Err: &transport.IOError{
							Operation: transport.IOTransmit, Err: cause,
						}}
					}

					return success(metadata), nil
				},
				close: func() error { closes++; return closeErr },
			})

			t.Cleanup(func() {
				if err := d.Close(); !errors.Is(err, closeErr) {
					t.Errorf("cleanup Close = %v, want close cause", err)
				}
			})

			var err error
			if test.template {
				err = d.ImportKeyWithTemplate(t.Context(), protocol.ControlReferenceTemplate{
					Tag: protocol.AuthenticationTemplateTag, KeyReference: protocol.AuthenticationKeyReference,
				}, attributes, key, nil)
			} else {
				err = d.ImportKey(t.Context(), protocol.AuthenticationTemplateTag, key, nil)
			}

			var (
				invalidated *transport.DeviceInvalidatedError
				ioError     *transport.IOError
			)
			if !errors.As(err, &invalidated) || !errors.As(err, &ioError) ||
				ioError.Operation != transport.IOTransmit || !errors.Is(err, cause) || !errors.Is(err, closeErr) {
				t.Fatalf("import error = %v, want invalidation with transmit and close causes", err)
			}

			if _, err := d.GetData(t.Context(), protocol.URLObject); !errors.Is(err, io.ErrClosedPipe) {
				t.Errorf("next operation error = %v, want closed pipe", err)
			}

			if err := d.Close(); !errors.Is(err, closeErr) {
				t.Errorf("Close = %v, want close cause", err)
			}

			if !bytes.Equal(instructions, test.want) || closes != 1 {
				t.Errorf("instructions = %x, closes = %d; want %x, 1", instructions, closes, test.want)
			}
		})
	}
}

func importTestKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()

	scalar := [32]byte{31: 1}

	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar[:])
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func importTestApplication(attributes []byte) []byte {
	contents := bertlv.Append(nil, 0x4f, []byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 6, 0, 0, 0, 1, 0, 0})
	contents = bertlv.Append(contents, 0x73, bertlv.Append(nil, 0xc3, attributes))

	return bertlv.Append(nil, 0x6e, contents)
}
