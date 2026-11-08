package client_test

import (
	"errors"
	"io"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestUserInteractionFlagWire(t *testing.T) {
	application := []byte{
		0x4f, 0x10, 0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 6, 0, 0, 0, 1, 0, 0,
		0x73, 0x0c, 0xd6, 2, 1, 0x20, 0xd7, 2, 0, 0, 0xd8, 2, 2, 0x10,
	}

	for _, object := range []struct {
		name    string
		object  protocol.Object
		address [2]byte
		flag    protocol.UserInteractionFlag
		value   [2]byte
		direct  bool
	}{
		{
			name: "SIG", object: protocol.SignatureUIFObject, address: [2]byte{0, 0xd6},
			flag: protocol.UserInteractionFlag{State: protocol.UIFEnabled, Features: protocol.GeneralFeatureButton}, value: [2]byte{1, 0x20},
		},
		{
			name: "DEC zero features", object: protocol.DecryptionUIFObject, address: [2]byte{0, 0xd7},
			flag: protocol.UserInteractionFlag{State: protocol.UIFDisabled}, value: [2]byte{0, 0},
		},
		{
			name: "AUT permanent", object: protocol.AuthenticationUIFObject, address: [2]byte{0, 0xd8},
			flag: protocol.UserInteractionFlag{State: protocol.UIFPermanentlyEnabled, Features: protocol.GeneralFeatureKeypad}, value: [2]byte{2, 0x10},
		},
		{
			name: "proprietary unknown state", object: 0xdf20, address: [2]byte{0xdf, 0x20}, direct: true,
			flag: protocol.UserInteractionFlag{State: 0x7f, Features: 0x81}, value: [2]byte{0x7f, 0x81},
		},
	} {
		for _, extended := range []bool{false, true} {
			name := object.name + "/short"
			if extended {
				name = object.name + "/extended"
			}

			t.Run(name, func(t *testing.T) {
				address, response := [2]byte{0, 0x6e}, application
				if object.direct {
					address, response = object.address, object.value[:]
				}

				get := []byte{0, 0xca, address[0], address[1], 0}
				put := []byte{0, 0xda, object.address[0], object.address[1], 2, object.value[0], object.value[1]}

				if extended {
					get = []byte{0, 0xca, address[0], address[1], 0, 0, 0}
					put = []byte{0, 0xda, object.address[0], object.address[1], 0, 0, 2, object.value[0], object.value[1]}
				}

				requests := []step{
					{command: get, response: iso7816.Response{Status: 0x9000, Data: response}},
					{command: put, response: iso7816.Response{Status: 0x9000}},
				}

				var c *client.Client
				if extended {
					c = newExtendedClient(t, requests...)
				} else {
					c = newClient(t, requests...)
				}

				got, err := c.GetUserInteractionFlag(t.Context(), object.object)
				if err != nil || got != object.flag {
					t.Fatalf("flag = %+v, %v; want %+v", got, err, object.flag)
				}

				if err := c.PutUserInteractionFlag(t.Context(), object.object, got); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestUserInteractionFlagErrors(t *testing.T) {
	for _, test := range []struct {
		name       string
		put        bool
		response   iso7816.Response
		err        error
		wantError  error
		wantStatus iso7816.StatusWord
	}{
		{name: "empty GET", response: iso7816.Response{Status: 0x9000}, wantError: protocol.ErrInvalidResponse},
		{name: "short GET", response: iso7816.Response{Status: 0x9000, Data: []byte{1}}, wantError: protocol.ErrInvalidResponse},
		{name: "long GET", response: iso7816.Response{Status: 0x9000, Data: []byte{1, 0x20, 0}}, wantError: protocol.ErrInvalidResponse},
		{name: "unavailable GET", response: iso7816.Response{Status: 0x6a88}, wantStatus: 0x6a88},
		{name: "GET transport", err: io.ErrUnexpectedEOF, wantError: io.ErrUnexpectedEOF},
		{name: "PUT not verified", put: true, response: iso7816.Response{Status: 0x6982}, wantStatus: 0x6982},
		{name: "PUT rejected", put: true, response: iso7816.Response{Status: 0x6985}, wantStatus: 0x6985},
		{name: "PUT response data", put: true, response: iso7816.Response{Status: 0x9000, Data: []byte{1}}, wantError: protocol.ErrInvalidResponse},
		{name: "PUT transport", put: true, err: io.ErrUnexpectedEOF, wantError: io.ErrUnexpectedEOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := []byte{0, 0xca, 0xdf, 0x20, 0}
			if test.put {
				wire = []byte{0, 0xda, 0, 0xd6, 2, 2, 0x20}
			}

			c := newClient(t, step{command: wire, response: test.response, err: test.err})

			var err error
			if test.put {
				err = c.PutUserInteractionFlag(t.Context(), protocol.SignatureUIFObject, protocol.UserInteractionFlag{
					State: protocol.UIFPermanentlyEnabled, Features: protocol.GeneralFeatureButton,
				})
			} else {
				_, err = c.GetUserInteractionFlag(t.Context(), 0xdf20)
			}

			if test.wantError != nil {
				if !errors.Is(err, test.wantError) {
					t.Errorf("error = %v, want %v", err, test.wantError)
				}
			} else {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != test.wantStatus {
					t.Errorf("error = %v, want APDU error %s", err, test.wantStatus)
				}
			}
		})
	}
}

func TestUserInteractionFlagMissingFromApplicationData(t *testing.T) {
	c := newClient(t,
		step{command: []byte{0, 0xca, 0, 0x6e, 0}, response: iso7816.Response{Status: 0x9000, Data: signatureApplication}},
		step{command: []byte{0, 0xca, 0, 0xd7, 0}, response: iso7816.Response{Status: 0x9000, Data: []byte{0x7f, 0x81}}},
	)

	got, err := c.GetUserInteractionFlag(t.Context(), protocol.DecryptionUIFObject)
	if err != nil || got.State != 0x7f || got.Features != 0x81 {
		t.Fatalf("individual UIF = %+v, %v", got, err)
	}
}

func TestAttestationUserInteractionFlagReadDirectly(t *testing.T) {
	c := newClient(t, step{
		command: []byte{0, 0xca, 0, 0xd9, 0}, response: iso7816.Response{Status: 0x9000, Data: []byte{0x7f, 0}},
	})

	got, err := c.GetUserInteractionFlag(t.Context(), protocol.AttestationUIFObject)
	if err != nil || got.State != 0x7f || got.Features != 0 {
		t.Fatalf("attestation UIF = %+v, %v", got, err)
	}
}

func TestUserInteractionFlagApplicationErrorDoesNotFallBack(t *testing.T) {
	for _, test := range []struct {
		name       string
		response   iso7816.Response
		err        error
		wantError  error
		wantStatus iso7816.StatusWord
	}{
		{name: "malformed", response: iso7816.Response{Status: 0x9000, Data: []byte{0x4f, 0x10, 0xd2}}, wantError: protocol.ErrInvalidResponse},
		{name: "APDU", response: iso7816.Response{Status: 0x6a88}, wantStatus: 0x6a88},
		{name: "transport", err: io.ErrUnexpectedEOF, wantError: io.ErrUnexpectedEOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := newClient(t, step{command: []byte{0, 0xca, 0, 0x6e, 0}, response: test.response, err: test.err})

			_, err := c.GetUserInteractionFlag(t.Context(), protocol.SignatureUIFObject)

			if test.wantError != nil {
				if !errors.Is(err, test.wantError) {
					t.Errorf("error = %v, want %v", err, test.wantError)
				}
			} else {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != test.wantStatus {
					t.Errorf("error = %v, want APDU error %s", err, test.wantStatus)
				}
			}
		})
	}
}
