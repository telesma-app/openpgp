package client_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
)

type step struct {
	command  []byte
	response iso7816.Response
	err      error
}

type peer struct {
	t     *testing.T
	steps []step
	index int
}

func newClient(t *testing.T, steps ...step) *client.Client {
	t.Helper()
	p := &peer{t: t, steps: steps}
	t.Cleanup(func() {
		if p.index != len(p.steps) {
			t.Errorf("exchanges = %d, want %d", p.index, len(p.steps))
		}
	})

	return client.NewClient(p)
}

func newExtendedClient(t *testing.T, steps ...step) *client.Client {
	t.Helper()
	p := &peer{t: t, steps: steps}
	t.Cleanup(func() {
		if p.index != len(p.steps) {
			t.Errorf("exchanges = %d, want %d", p.index, len(p.steps))
		}
	})

	return client.NewClient(p, client.WithExtendedLength())
}

func (p *peer) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	p.t.Helper()

	if p.index == len(p.steps) {
		p.t.Fatalf("unexpected command INS=%02x", command.INS)
	}

	s := p.steps[p.index]
	p.index++

	raw, err := command.MarshalBinary()
	if err != nil {
		p.t.Fatal(err)
	}

	if !bytes.Equal(raw, s.command) {
		p.t.Errorf("command = %x, want %x", raw, s.command)
	}

	return s.response, s.err
}

// Application Related Data containing a 3.4 AID and the SIG P-256 attributes.
var signatureApplication = []byte{
	0x6e, 0x1f, 0x4f, 0x10, 0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 0, 0, 0, 0, 1, 0, 0,
	0x73, 0x0b, 0xc1, 9, 19, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7,
}
