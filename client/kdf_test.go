package client_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"slices"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestKDFCommandWire(t *testing.T) {
	// The GET response may include F9, but PUT DATA carries only its children.
	body := []byte{
		0x81, 1, 3, 0x82, 1, 8, 0x83, 4, 0, 1, 0x86, 0xa0,
		0x84, 8, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x85, 8, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x86, 8, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
	}

	for _, test := range []struct {
		name string
		new  func(*testing.T, ...step) *client.Client
		get  []byte
		put  []byte
	}{
		{
			name: "short", new: newClient,
			get: []byte{0, 0xca, 0, 0xf9, 0},
			put: []byte{0, 0xda, 0, 0xf9, 0x2a},
		},
		{
			name: "extended", new: newExtendedClient,
			get: []byte{0, 0xca, 0, 0xf9, 0, 0, 0},
			put: []byte{0, 0xda, 0, 0xf9, 0, 0, 0x2a},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := slices.Concat([]byte{0xf9, 0x2a}, body)
			c := test.new(t,
				step{command: test.get, response: iso7816.Response{Status: 0x9000, Data: response}},
				step{command: slices.Concat(test.put, body), response: iso7816.Response{Status: 0x9000}},
			)

			got, err := c.GetKDF(t.Context())
			if err != nil {
				t.Fatal(err)
			}

			if err := c.PutKDF(t.Context(), got); err != nil {
				t.Fatal(err)
			}

			want := protocol.KDF{
				Raw: response, Algorithm: protocol.KDFIterSaltedS2K,
				HashAlgorithm: protocol.KDFHashSHA256, IterationCount: 100000,
				PW1Salt: body[14:22], ResettingCodeSalt: body[24:32], PW3Salt: body[34:42],
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("KDF after PUT = %+v, want %+v", got, want)
			}
		})
	}
}

func TestGetKDFMetadataAndErrors(t *testing.T) {
	for _, test := range []struct {
		name      string
		data      []byte
		status    iso7816.StatusWord
		err       error
		algorithm protocol.KDFAlgorithm
		wantError error
	}{
		{name: "NONE", data: []byte{0x81, 1, 0}, status: 0x9000, algorithm: protocol.KDFNone},
		{name: "unknown algorithm", data: []byte{0x81, 1, 0x7f}, status: 0x9000, algorithm: 0x7f},
		{name: "empty", status: 0x9000, algorithm: protocol.KDFNone},
		{name: "empty wrapped", data: []byte{0xf9, 0}, status: 0x9000, algorithm: protocol.KDFNone},
		{name: "malformed", data: []byte{0x81, 2, 0}, status: 0x9000, wantError: protocol.ErrInvalidResponse},
		{name: "unavailable", status: 0x6a88},
		{name: "transport", err: io.ErrUnexpectedEOF, wantError: io.ErrUnexpectedEOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := newClient(t, step{
				command:  []byte{0, 0xca, 0, 0xf9, 0},
				response: iso7816.Response{Status: test.status, Data: test.data}, err: test.err,
			})

			got, err := c.GetKDF(t.Context())

			if test.wantError != nil {
				if !errors.Is(err, test.wantError) {
					t.Fatalf("error = %v, want %v", err, test.wantError)
				}
			} else if test.status == 0x6a88 {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6a88 {
					t.Fatalf("error = %v, want APDU error 6a88", err)
				}
			} else if err != nil || got.Algorithm != test.algorithm || !bytes.Equal(got.Raw, test.data) {
				t.Fatalf("KDF = %+v, %v", got, err)
			}
		})
	}
}

func TestPutKDFClearsEncodedPayloadWithoutChangingInput(t *testing.T) {
	for _, test := range []struct {
		name      string
		response  iso7816.Response
		err       error
		wantError error
	}{
		{name: "success", response: iso7816.Response{Status: 0x9000}},
		{name: "APDU", response: iso7816.Response{Status: 0x6982}},
		{name: "unexpected response", response: iso7816.Response{Status: 0x9000, Data: []byte{1}}, wantError: protocol.ErrInvalidResponse},
		{name: "transport", err: io.ErrUnexpectedEOF, wantError: io.ErrUnexpectedEOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			initial := bytes.Repeat([]byte{0x5a}, 32)
			p := &kdfPutPeer{
				t: t, want: slices.Concat([]byte{0, 0xda, 0, 0xf9, 0x25, 0x81, 1, 0, 0x87, 0x20}, initial),
				response: test.response, err: test.err,
			}
			c := client.NewClient(p)

			err := c.PutKDF(t.Context(), protocol.KDF{Algorithm: protocol.KDFNone, InitialPW1Hash: initial})

			if test.wantError != nil {
				if !errors.Is(err, test.wantError) {
					t.Errorf("error = %v, want %v", err, test.wantError)
				}
			} else if test.response.Status == 0x6982 {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6982 {
					t.Errorf("error = %v, want APDU error 6982", err)
				}
			} else if err != nil {
				t.Error(err)
			}

			if p.calls != 1 || len(p.payload) != 37 || !bytes.Equal(p.payload, make([]byte, 37)) {
				t.Errorf("calls = %d, payload after PUT = %x; want one call and cleared payload", p.calls, p.payload)
			}

			if !bytes.Equal(initial, bytes.Repeat([]byte{0x5a}, 32)) {
				t.Error("PUT changed the borrowed initial hash")
			}
		})
	}
}

type kdfPutPeer struct {
	t        testing.TB
	want     []byte
	response iso7816.Response
	err      error
	payload  []byte
	calls    int
}

func (p *kdfPutPeer) Exchange(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
	p.t.Helper()
	p.calls++
	p.payload = command.Data

	raw, err := command.MarshalBinary()
	if err != nil {
		p.t.Fatal(err)
	}

	if !bytes.Equal(raw, p.want) {
		p.t.Errorf("command = %x, want %x", raw, p.want)
	}

	return p.response, p.err
}
