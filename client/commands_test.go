package client_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"errors"
	"io"
	"slices"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestSelectAndGetData(t *testing.T) {
	data := []byte("https://example.org/key.asc")
	c := newClient(t,
		step{command: []byte{0, 0xa4, 4, 0, 6, 0xd2, 0x76, 0, 1, 0x24, 1, 0}, response: iso7816.Response{Status: 0x9000, Data: []byte{0x6f, 0}}},
		step{command: []byte{0, 0xca, 0x5f, 0x50, 0}, response: iso7816.Response{Status: 0x9000, Data: data}},
	)

	if err := c.Select(t.Context()); err != nil {
		t.Fatal(err)
	}

	got, err := c.GetData(t.Context(), protocol.URLObject)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, data) {
		t.Errorf("GET DATA = %q, want %q", got, data)
	}
}

func TestReferenceStatusAndRetryIdentity(t *testing.T) {
	c := newClient(t,
		step{command: []byte{0, 0x20, 0, 0x81}, response: iso7816.Response{Status: 0x63c3}},
		step{command: []byte{0, 0x20, 0, 0x82, 6, '1', '2', '3', '4', '5', '6'}, response: iso7816.Response{Status: 0x63c2}},
		step{command: []byte{0, 0x20, 0, 0x83}, response: iso7816.Response{Status: 0x6983}},
		step{command: []byte{0, 0x20, 0xff, 0x82}, response: iso7816.Response{Status: 0x9000}},
	)

	status, err := c.ReferenceStatus(t.Context(), protocol.PW1Sign)
	if err != nil || status.Verified || status.Retries != 3 {
		t.Fatalf("status = %+v, error = %v", status, err)
	}

	err = c.Verify(t.Context(), protocol.PW1, []byte("123456"))

	var (
		retry *client.ReferenceDataError
		apdu  *iso7816.APDUError
	)

	if !errors.As(err, &retry) || retry.Retries != 2 || retry.Reference != protocol.PW1 {
		t.Fatalf("VERIFY error = %v", err)
	}

	if !errors.As(err, &apdu) || apdu.StatusWord() != 0x63c2 {
		t.Errorf("APDU error = %v", err)
	}

	_, err = c.ReferenceStatus(t.Context(), protocol.PW3)
	if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6983 {
		t.Errorf("blocked reference error = %v", err)
	}

	if err := c.ResetSecurityStatus(t.Context(), protocol.PW1); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordChanges(t *testing.T) {
	c := newClient(t,
		step{command: []byte{0, 0x24, 0, 0x81, 12, '1', '2', '3', '4', '5', '6', '6', '5', '4', '3', '2', '1'}, response: iso7816.Response{Status: 0x9000}},
		step{command: []byte{0, 0x2c, 0, 0x81, 14, '1', '2', '3', '4', '5', '6', '7', '8', '6', '5', '4', '3', '2', '1'}, response: iso7816.Response{Status: 0x63c1}},
		step{command: []byte{0, 0x2c, 2, 0x81, 6, '6', '5', '4', '3', '2', '1'}, response: iso7816.Response{Status: 0x9000}},
	)

	current, replacement := []byte("123456"), []byte("654321")
	if err := c.ChangeReferenceData(t.Context(), protocol.PW1Sign, current, replacement); err != nil {
		t.Fatal(err)
	}

	if string(current) != "123456" || string(replacement) != "654321" {
		t.Fatal("borrowed password buffers changed")
	}

	err := c.ResetRetryCounter(t.Context(), []byte("12345678"), replacement)

	var retry *client.ReferenceDataError
	if !errors.As(err, &retry) || retry.Reference != 0 || retry.Retries != 1 {
		t.Errorf("resetting-code error = %v", err)
	}

	if err := c.ResetRetryCounterWithPW3(t.Context(), replacement); err != nil {
		t.Fatal(err)
	}
}

func TestReadErrorIdentity(t *testing.T) {
	for _, tt := range []struct {
		name string
		step step
		want error
	}{
		{name: "transport", step: step{command: []byte{0, 0xca, 0x5f, 0x50, 0}, err: io.ErrUnexpectedEOF}, want: io.ErrUnexpectedEOF},
		{name: "APDU", step: step{command: []byte{0, 0xca, 0x5f, 0x50, 0}, response: iso7816.Response{Status: 0x6a88}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newClient(t, tt.step)

			_, err := c.GetData(t.Context(), protocol.URLObject)
			if tt.want != nil {
				if !errors.Is(err, tt.want) {
					t.Fatalf("error = %v, want %v", err, tt.want)
				}
			} else {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6a88 {
					t.Fatalf("APDU error = %v", err)
				}
			}
		})
	}
}

func TestGetNextData(t *testing.T) {
	for _, tt := range []struct {
		name     string
		response iso7816.Response
		err      error
	}{
		{name: "certificate", response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 1, 2}}},
		{name: "empty", response: iso7816.Response{Status: 0x9000}},
		{name: "unavailable", response: iso7816.Response{Status: 0x6a88}},
		{name: "transport", err: io.ErrUnexpectedEOF},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newClient(t, step{
				command: []byte{0, 0xcc, 0x7f, 0x21, 0}, response: tt.response, err: tt.err,
			})

			got, err := c.GetNextData(t.Context())

			switch {
			case tt.err != nil:
				if !errors.Is(err, tt.err) {
					t.Fatalf("error = %v, want %v", err, tt.err)
				}
			case tt.response.Status != 0x9000:
				var apduError *iso7816.APDUError
				if !errors.As(err, &apduError) || apduError.StatusWord() != tt.response.Status {
					t.Fatalf("error = %v, want APDU error %s", err, tt.response.Status)
				}
			default:
				if err != nil || !bytes.Equal(got, tt.response.Data) {
					t.Fatalf("certificate = %x, %v; want %x", got, err, tt.response.Data)
				}
			}
		})
	}
}

func TestPutDataAndSelectOccurrence(t *testing.T) {
	c := newClient(t,
		step{command: []byte{0, 0xa5, 2, 4, 6, 0x60, 4, 0x5c, 2, 0x7f, 0x21, 0}, response: iso7816.Response{Status: 0x9000, Data: []byte{0x60, 0}}},
		step{command: []byte{0, 0xda, 0x7f, 0x21, 3, 1, 2, 3}, response: iso7816.Response{Status: 0x9000}},
		step{command: []byte{0, 0xda, 0x5f, 0x50}, response: iso7816.Response{Status: 0x9000}},
	)
	if err := c.SelectData(t.Context(), protocol.CardholderCertificateObject, 2); err != nil {
		t.Fatal(err)
	}

	if err := c.PutData(t.Context(), protocol.CardholderCertificateObject, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}

	if err := c.PutData(t.Context(), protocol.URLObject, nil); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateKeyCommandWire(t *testing.T) {
	for _, tt := range []struct {
		name    string
		command []byte
		call    func(*client.Client) ([]byte, error)
	}{
		{name: "signature", command: []byte{0, 0x2a, 0x9e, 0x9a, 3, 1, 2, 3, 0}, call: func(c *client.Client) ([]byte, error) { return c.ComputeDigitalSignature(t.Context(), []byte{1, 2, 3}) }},
		{name: "authenticate", command: []byte{0, 0x88, 0, 0, 3, 1, 2, 3, 0}, call: func(c *client.Client) ([]byte, error) { return c.InternalAuthenticate(t.Context(), []byte{1, 2, 3}) }},
		{name: "decipher", command: []byte{0, 0x2a, 0x80, 0x86, 3, 0, 2, 3, 0}, call: func(c *client.Client) ([]byte, error) { return c.Decipher(t.Context(), []byte{0, 2, 3}) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newClient(t, step{command: tt.command, response: iso7816.Response{Status: 0x9000, Data: []byte{4, 5}}})

			got, err := tt.call(c)
			if err != nil || !bytes.Equal(got, []byte{4, 5}) {
				t.Fatalf("result = %x, error = %v", got, err)
			}
		})
	}
}

func TestGenerationAcknowledgedWithMalformedPublicKey(t *testing.T) {
	c := newClient(t,
		step{command: []byte{0, 0xca, 0, 0x6e, 0}, response: iso7816.Response{Status: 0x9000, Data: signatureApplication}},
		step{command: []byte{0, 0x47, 0x80, 0, 2, 0xb6, 0, 0}, response: iso7816.Response{Status: 0x9000, Data: []byte{0x7f}}},
	)
	_, err := c.GenerateAsymmetricKeyPair(t.Context(), protocol.DigitalSignatureTemplateTag)

	var generated *client.KeyGenerationError
	if !errors.As(err, &generated) || generated.Template != (protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag}) || !errors.Is(err, protocol.ErrInvalidResponse) {
		t.Fatalf("generation error = %v", err)
	}
}

func TestGenerationRejectsUnsupportedCardAlgorithmBeforeReplacement(t *testing.T) {
	// An unknown algorithm ID is valid metadata but cannot be parsed into a Go
	// public key. No GENERATE command should be sent after discovering it.
	application := []byte{
		0x6e, 0x17, 0x4f, 0x10, 0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 0, 0, 0, 0, 1, 0, 0,
		0x73, 3, 0xc1, 1, 99,
	}
	c := newClient(t, step{command: []byte{0, 0xca, 0, 0x6e, 0}, response: iso7816.Response{Status: 0x9000, Data: application}})

	_, err := c.GenerateAsymmetricKeyPair(t.Context(), protocol.DigitalSignatureTemplateTag)
	if !errors.Is(err, protocol.ErrUnsupportedAlgorithm) {
		t.Fatalf("generation error = %v", err)
	}
}

func TestGenerationTransportFailureHasUnknownEffect(t *testing.T) {
	c := newClient(t,
		step{command: []byte{0, 0xca, 0, 0x6e, 0}, response: iso7816.Response{Status: 0x9000, Data: signatureApplication}},
		step{command: []byte{0, 0x47, 0x80, 0, 2, 0xb6, 0, 0}, err: io.ErrUnexpectedEOF},
	)
	_, err := c.GenerateAsymmetricKeyPair(t.Context(), protocol.DigitalSignatureTemplateTag)

	var generated *client.KeyGenerationError
	if !errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &generated) {
		t.Fatalf("generation error = %v", err)
	}
}

func TestReadExistingPublicKey(t *testing.T) {
	scalar := [32]byte{31: 1}

	key, err := ecdh.P256().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatal(err)
	}

	point := key.PublicKey().Bytes()
	response := slices.Concat([]byte{0x7f, 0x49, 67, 0x86, 65}, point)
	c := newClient(t,
		step{command: []byte{0, 0xca, 0, 0x6e, 0}, response: iso7816.Response{Status: 0x9000, Data: signatureApplication}},
		step{command: []byte{0, 0x47, 0x81, 0, 2, 0xb6, 0, 0}, response: iso7816.Response{Status: 0x9000, Data: response}},
	)

	public, err := c.ReadPublicKey(t.Context(), protocol.DigitalSignatureTemplateTag)
	if err != nil {
		t.Fatal(err)
	}

	got, ok := public.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T", public)
	}

	encoded, err := got.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(encoded, point) {
		t.Errorf("public key = %v", public)
	}
}

func TestGetChallengeChecksLength(t *testing.T) {
	c := newClient(t,
		step{command: []byte{0, 0x84, 0, 0, 4}, response: iso7816.Response{Status: 0x9000, Data: []byte{1, 2, 3, 4}}},
		step{command: []byte{0, 0x84, 0, 0, 4}, response: iso7816.Response{Status: 0x9000, Data: []byte{1, 2, 3}}},
	)

	data, err := c.GetChallenge(t.Context(), 4)
	if err != nil || len(data) != 4 {
		t.Fatalf("challenge = %x, error = %v", data, err)
	}

	if _, err := c.GetChallenge(t.Context(), 4); !errors.Is(err, protocol.ErrInvalidResponse) {
		t.Fatalf("short challenge error = %v", err)
	}
}
