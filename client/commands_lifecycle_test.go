package client_test

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestLifecycleCommands(t *testing.T) {
	for _, command := range []struct {
		name        string
		instruction byte
		call        func(*client.Client, context.Context) error
	}{
		{name: "terminate", instruction: 0xe6, call: (*client.Client).TerminateDF},
		{name: "activate", instruction: 0x44, call: (*client.Client).ActivateFile},
	} {
		t.Run(command.name, func(t *testing.T) {
			for _, test := range []struct {
				name       string
				response   iso7816.Response
				failure    error
				want       error
				wantStatus iso7816.StatusWord
			}{
				{name: "success", response: iso7816.Response{Status: 0x9000}},
				{name: "denied", response: iso7816.Response{Status: 0x6982}, wantStatus: 0x6982},
				{name: "unsupported", response: iso7816.Response{Status: 0x6d00}, wantStatus: 0x6d00},
				{
					name:     "unexpected response data",
					response: iso7816.Response{Status: 0x9000, Data: []byte{0x01}},
					want:     protocol.ErrInvalidResponse,
				},
				{name: "transport failure", failure: io.ErrUnexpectedEOF, want: io.ErrUnexpectedEOF},
			} {
				t.Run(test.name, func(t *testing.T) {
					c := newClient(t, step{
						command:  []byte{0x00, command.instruction, 0x00, 0x00},
						response: test.response,
						err:      test.failure,
					})

					err := command.call(c, t.Context())

					if test.wantStatus != 0 {
						var apduError *iso7816.APDUError
						if !errors.As(err, &apduError) || apduError.StatusWord() != test.wantStatus {
							t.Fatalf("error = %v, want APDU error %s", err, test.wantStatus)
						}
					} else if !errors.Is(err, test.want) {
						t.Fatalf("error = %v, want %v", err, test.want)
					}
				})
			}
		})
	}
}

func TestExtendedLifecycleCommandsRemainCaseOne(t *testing.T) {
	p := &peer{t: t, steps: []step{
		{command: []byte{0x00, 0xe6, 0x00, 0x00}, response: iso7816.Response{Status: 0x9000}},
		{command: []byte{0x00, 0x44, 0x00, 0x00}, response: iso7816.Response{Status: 0x9000}},
	}}
	t.Cleanup(func() {
		if p.index != len(p.steps) {
			t.Errorf("exchanges = %d, want %d", p.index, len(p.steps))
		}
	})

	c := client.NewClient(p, client.WithExtendedLength())

	if err := c.TerminateDF(t.Context()); err != nil {
		t.Fatal(err)
	}

	if err := c.ActivateFile(t.Context()); err != nil {
		t.Fatal(err)
	}
}
