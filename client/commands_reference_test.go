package client_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestReferenceStatus(t *testing.T) {
	for _, test := range []struct {
		name      string
		reference protocol.PasswordReference
		status    iso7816.StatusWord
		want      client.ReferenceStatus
	}{
		{
			name: "verified", reference: protocol.PW1Sign, status: 0x9000,
			want: client.ReferenceStatus{Verified: true},
		},
		{
			name: "no retries", reference: protocol.PW1, status: 0x63c0,
			want: client.ReferenceStatus{Retries: 0},
		},
		{
			name: "three retries", reference: protocol.PW1Sign, status: 0x63c3,
			want: client.ReferenceStatus{Retries: 3},
		},
		{
			name: "maximum retry nibble", reference: protocol.PW3, status: 0x63cf,
			want: client.ReferenceStatus{Retries: 15},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := newClient(t, step{
				command: []byte{0, 0x20, 0, byte(test.reference)}, response: iso7816.Response{Status: test.status},
			})

			got, err := c.ReferenceStatus(t.Context(), test.reference)
			if err != nil || got != test.want {
				t.Errorf("ReferenceStatus = %+v, %v; want %+v, nil", got, err, test.want)
			}
		})
	}
}

func TestReferenceStatusRejectsResponseData(t *testing.T) {
	for _, test := range []struct {
		name   string
		status iso7816.StatusWord
	}{
		{name: "verified with data", status: 0x9000},
		{name: "retries with data", status: 0x63c3},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := newClient(t, step{
				command: []byte{0, 0x20, 0, 0x81}, response: iso7816.Response{Status: test.status, Data: []byte{1}},
			})

			got, err := c.ReferenceStatus(t.Context(), protocol.PW1Sign)
			if !errors.Is(err, protocol.ErrInvalidResponse) || got != (client.ReferenceStatus{}) {
				t.Errorf("ReferenceStatus = %+v, %v; want zero result and invalid response", got, err)
			}
		})
	}
}

func TestReferenceStatusPreservesErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		status iso7816.StatusWord
		cause  error
	}{
		{name: "blocked reference", status: 0x6983},
		{name: "non-retry warning", status: 0x63d3},
		{name: "transport failure", cause: io.ErrUnexpectedEOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := newClient(t, step{
				command: []byte{0, 0x20, 0, 0x83}, response: iso7816.Response{Status: test.status}, err: test.cause,
			})

			got, err := c.ReferenceStatus(t.Context(), protocol.PW3)
			if got != (client.ReferenceStatus{}) {
				t.Errorf("ReferenceStatus result = %+v, want zero result", got)
			}

			if test.cause != nil {
				if !errors.Is(err, test.cause) {
					t.Errorf("ReferenceStatus error = %v, want cause %v", err, test.cause)
				}
			} else {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != test.status {
					t.Errorf("ReferenceStatus error = %v, want APDU error %s", err, test.status)
				}
			}

			var retry *client.ReferenceDataError
			if errors.As(err, &retry) {
				t.Errorf("ReferenceStatus error = %v, want no reference data error", err)
			}
		})
	}
}

func TestVerifyRetryIdentity(t *testing.T) {
	c := newClient(t, step{
		command: []byte{0, 0x20, 0, 0x82, 6, '1', '2', '3', '4', '5', '6'}, response: iso7816.Response{Status: 0x63c2},
	})

	err := c.Verify(t.Context(), protocol.PW1, []byte("123456"))

	var retry *client.ReferenceDataError
	if !errors.As(err, &retry) {
		t.Fatalf("VERIFY error = %v, want reference data error", err)
	}

	if retry.Reference != protocol.PW1 || retry.Retries != 2 || retry.Status != 0x63c2 {
		t.Errorf("reference data error = %+v, want PW1, 2 retries and status 63c2", retry)
	}

	var apdu *iso7816.APDUError
	if !errors.As(err, &apdu) || apdu.StatusWord() != 0x63c2 {
		t.Errorf("VERIFY error = %v, want APDU error 63c2", err)
	}
}

func TestResetSecurityStatus(t *testing.T) {
	c := newClient(t, step{
		command: []byte{0, 0x20, 0xff, 0x82}, response: iso7816.Response{Status: 0x9000},
	})

	if err := c.ResetSecurityStatus(t.Context(), protocol.PW1); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordChangesClearPayloadWithoutChangingInputs(t *testing.T) {
	for _, operation := range []struct {
		name           string
		credential     string
		wire           []byte
		retryReference protocol.PasswordReference
		call           func(context.Context, *client.Client, []byte, []byte) error
	}{
		{
			name: "ChangeReferenceData", credential: "123456", retryReference: protocol.PW1Sign,
			wire: []byte{0, 0x24, 0, 0x81, 12, '1', '2', '3', '4', '5', '6', '6', '5', '4', '3', '2', '1'},
			call: func(ctx context.Context, c *client.Client, current, replacement []byte) error {
				return c.ChangeReferenceData(ctx, protocol.PW1Sign, current, replacement)
			},
		},
		{
			name: "ResetRetryCounter", credential: "12345678", retryReference: 0,
			wire: []byte{0, 0x2c, 0, 0x81, 14, '1', '2', '3', '4', '5', '6', '7', '8', '6', '5', '4', '3', '2', '1'},
			call: func(ctx context.Context, c *client.Client, resettingCode, replacement []byte) error {
				return c.ResetRetryCounter(ctx, resettingCode, replacement)
			},
		},
	} {
		t.Run(operation.name, func(t *testing.T) {
			for _, test := range []struct {
				name      string
				response  iso7816.Response
				err       error
				wantError error
			}{
				{name: "success", response: iso7816.Response{Status: 0x9000}},
				{name: "retry failure", response: iso7816.Response{Status: 0x63c1}},
				{name: "APDU failure", response: iso7816.Response{Status: 0x6982}},
				{name: "malformed acknowledgement", response: iso7816.Response{Status: 0x9000, Data: []byte{1}}, wantError: protocol.ErrInvalidResponse},
				{name: "transport failure", err: io.ErrUnexpectedEOF, wantError: io.ErrUnexpectedEOF},
			} {
				t.Run(test.name, func(t *testing.T) {
					// Spare capacity exposes reuse of caller-owned storage.
					credential := []byte(operation.credential + " reserved")
					replacement := []byte("654321 reserved")
					credentialBefore := slices.Clone(credential)
					replacementBefore := slices.Clone(replacement)
					p := &passwordCommandPeer{t: t, want: operation.wire, response: test.response, err: test.err}
					c := client.NewClient(p)

					err := operation.call(t.Context(), c, credential[:len(operation.credential)], replacement[:6])

					switch {
					case test.wantError != nil:
						if !errors.Is(err, test.wantError) {
							t.Errorf("error = %v, want %v", err, test.wantError)
						}
					case test.response.Status == 0x63c1:
						var retry *client.ReferenceDataError
						if !errors.As(err, &retry) || retry.Reference != operation.retryReference || retry.Retries != 1 || retry.Status != 0x63c1 {
							t.Errorf("error = %v, want reference %02x, 1 retry and status 63c1", err, byte(operation.retryReference))
						}

						var apdu *iso7816.APDUError
						if !errors.As(err, &apdu) || apdu.StatusWord() != 0x63c1 {
							t.Errorf("error = %v, want APDU error 63c1", err)
						}
					case test.response.Status == 0x6982:
						var apdu *iso7816.APDUError
						if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6982 {
							t.Errorf("error = %v, want APDU error 6982", err)
						}
					default:
						if err != nil {
							t.Error(err)
						}
					}

					length := len(operation.credential) + 6
					if p.calls != 1 || len(p.payload) != length || !bytes.Equal(p.payload, make([]byte, length)) {
						t.Errorf("calls = %d, payload after return = %x; want one call and %d cleared bytes", p.calls, p.payload, length)
					}

					if !bytes.Equal(credential, credentialBefore) || !bytes.Equal(replacement, replacementBefore) {
						t.Error("borrowed credential or replacement storage changed")
					}
				})
			}
		})
	}
}

func TestResetRetryCounterWithPW3PreservesInput(t *testing.T) {
	c := newClient(t, step{
		command: []byte{0, 0x2c, 2, 0x81, 6, '6', '5', '4', '3', '2', '1'}, response: iso7816.Response{Status: 0x9000},
	})
	replacement := []byte("654321")

	if err := c.ResetRetryCounterWithPW3(t.Context(), replacement); err != nil {
		t.Error(err)
	}

	if string(replacement) != "654321" {
		t.Error("borrowed replacement changed")
	}
}

type passwordCommandPeer struct {
	t        testing.TB
	want     []byte
	response iso7816.Response
	err      error
	payload  []byte
	calls    int
}

func (p *passwordCommandPeer) Exchange(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
	p.t.Helper()
	p.calls++

	if p.calls != 1 {
		p.t.Fatal("unexpected repeated password command")
	}

	// Retain the original payload to observe its clearing after the call.
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

func TestPasswordCommandsUseExplicitPINBlock2Values(t *testing.T) {
	current, err := protocol.EncodePINBlock2("123456")
	if err != nil {
		t.Fatal(err)
	}

	replacement, err := protocol.EncodePINBlock2("654321")
	if err != nil {
		t.Fatal(err)
	}

	resettingCode, err := protocol.EncodePINBlock2("12345678")
	if err != nil {
		t.Fatal(err)
	}

	c := newClient(t,
		step{
			command:  []byte{0, 0x20, 0, 0x81, 8, 0x26, 0x12, 0x34, 0x56, 0xff, 0xff, 0xff, 0xff},
			response: iso7816.Response{Status: 0x9000},
		},
		step{
			command: []byte{0, 0x24, 0, 0x81, 16,
				0x26, 0x12, 0x34, 0x56, 0xff, 0xff, 0xff, 0xff,
				0x26, 0x65, 0x43, 0x21, 0xff, 0xff, 0xff, 0xff},
			response: iso7816.Response{Status: 0x9000},
		},
		step{
			command: []byte{0, 0x2c, 0, 0x81, 16,
				0x28, 0x12, 0x34, 0x56, 0x78, 0xff, 0xff, 0xff,
				0x26, 0x65, 0x43, 0x21, 0xff, 0xff, 0xff, 0xff},
			response: iso7816.Response{Status: 0x9000},
		},
		step{
			command:  []byte{0, 0x2c, 2, 0x81, 8, 0x26, 0x65, 0x43, 0x21, 0xff, 0xff, 0xff, 0xff},
			response: iso7816.Response{Status: 0x9000},
		},
	)

	if err := c.Verify(t.Context(), protocol.PW1Sign, current[:]); err != nil {
		t.Fatal(err)
	}

	if err := c.ChangeReferenceData(t.Context(), protocol.PW1Sign, current[:], replacement[:]); err != nil {
		t.Fatal(err)
	}

	if err := c.ResetRetryCounter(t.Context(), resettingCode[:], replacement[:]); err != nil {
		t.Fatal(err)
	}

	if err := c.ResetRetryCounterWithPW3(t.Context(), replacement[:]); err != nil {
		t.Fatal(err)
	}

	if current != [8]byte{0x26, 0x12, 0x34, 0x56, 0xff, 0xff, 0xff, 0xff} ||
		replacement != [8]byte{0x26, 0x65, 0x43, 0x21, 0xff, 0xff, 0xff, 0xff} ||
		resettingCode != [8]byte{0x28, 0x12, 0x34, 0x56, 0x78, 0xff, 0xff, 0xff} {
		t.Error("password commands changed borrowed PIN blocks")
	}
}
