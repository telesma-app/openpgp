package card

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

func TestAlgorithmMetadataReads(t *testing.T) {
	want := [][]byte{{0, 0xca, 0, 0xfa, 0}, {0, 0xca, 0, 0xda, 0}}

	var calls int

	d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
		raw, err := command.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}

		if calls >= len(want) {
			t.Fatalf("unexpected command = %x", raw)
		}

		if !bytes.Equal(raw, want[calls]) {
			t.Errorf("command = %x, want %x", raw, want[calls])
		}

		calls++

		if command.P2 == 0xfa {
			return success([]byte{0xfa, 5, 0xda, 3, 0x7f, 0x11, 0x22}), nil
		}

		return success([]byte{0x7f, 0x11, 0x22}), nil
	}})

	t.Cleanup(func() { _ = d.Close() })

	entries, err := d.GetAlgorithmInformation(t.Context())
	if err != nil || len(entries) != 1 || entries[0].Object != protocol.AttestationAlgorithmAttributesObject {
		t.Fatalf("information = %+v, %v", entries, err)
	}

	attributes, err := d.GetAlgorithmAttributes(t.Context(), entries[0].Object)
	if err != nil || attributes.Algorithm != 0x7f || !bytes.Equal(attributes.Raw, []byte{0x7f, 0x11, 0x22}) {
		t.Fatalf("attributes = %+v, %v", attributes, err)
	}

	if calls != len(want) {
		t.Errorf("exchanges = %d, want %d", calls, len(want))
	}
}

func TestPutAlgorithmAttributesAuthentication(t *testing.T) {
	cause := errors.New("password source failed")
	verify := []byte{0, 0x20, 0, 0x83, 11, 'e', 'n', 'c', 'o', 'd', 'e', 'd', ' ', 'P', 'W', '3'}
	put := []byte{0, 0xda, 0, 0xc1, 6, 1, 8, 0, 0, 0x20, 0}

	for _, test := range []struct {
		name         string
		authenticate bool
		sourceError  error
		verifyStatus iso7816.StatusWord
		commands     [][]byte
	}{
		{name: "current verification", commands: [][]byte{put}},
		{name: "source error", authenticate: true, sourceError: cause},
		{name: "wrong PW3", authenticate: true, verifyStatus: 0x63c2, commands: [][]byte{verify}},
		{name: "PW3 and replacement", authenticate: true, verifyStatus: 0x9000, commands: [][]byte{verify, put}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls, sourceCalls int

			password := []byte("encoded PW3")
			d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				raw, err := command.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}

				if calls >= len(test.commands) {
					t.Fatalf("unexpected command = %x", raw)
				}

				if !bytes.Equal(raw, test.commands[calls]) {
					t.Errorf("command = %x, want %x", raw, test.commands[calls])
				}

				calls++

				if command.INS == 0x20 {
					return iso7816.Response{Status: test.verifyStatus}, nil
				}

				return success(nil), nil
			}})

			t.Cleanup(func() { _ = d.Close() })

			var authentication AuthenticationSource
			if test.authenticate {
				authentication = func(context.Context) ([]byte, error) {
					sourceCalls++

					return password, test.sourceError
				}
			}

			err := d.PutAlgorithmAttributes(t.Context(), protocol.SignatureAlgorithmAttributesObject, protocol.AlgorithmAttributes{
				Algorithm: protocol.RSA, ModulusBits: 2048, ExponentBits: 32,
			}, authentication)

			if test.sourceError != nil {
				if !errors.Is(err, test.sourceError) {
					t.Errorf("error = %v, want source error %v", err, test.sourceError)
				}
			} else if test.verifyStatus == 0x63c2 {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != 0x63c2 {
					t.Errorf("error = %v, want PW3 verification failure 63c2", err)
				}
			} else if err != nil {
				t.Error(err)
			}

			if calls != len(test.commands) || (test.authenticate && sourceCalls != 1) {
				t.Errorf("exchanges = %d, source calls = %d", calls, sourceCalls)
			}

			if test.authenticate && test.sourceError == nil {
				if !bytes.Equal(password, make([]byte, len(password))) {
					t.Error("transferred password was not cleared")
				}
			} else if string(password) != "encoded PW3" {
				t.Error("password was changed without ownership transfer")
			}
		})
	}
}
