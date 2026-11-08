package client_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"slices"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
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

type keyImportPeer struct {
	t        testing.TB
	want     []byte
	response iso7816.Response
	err      error
	payload  []byte
	calls    int
}

func (p *keyImportPeer) Exchange(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
	p.t.Helper()

	p.calls++
	if p.calls != 1 {
		p.t.Fatal("import retried or sent an unexpected additional command")
	}

	if command.Le != 0 {
		p.t.Errorf("import Le = %d, want absent", command.Le)
	}

	raw, err := command.MarshalBinary()
	if err != nil {
		p.t.Fatal(err)
	}
	defer clear(raw)

	if !bytes.Equal(raw, p.want) {
		p.t.Error("import APDU differs from the independently constructed expected bytes")
	}
	// Keep the borrowed payload rather than cloning it to observe its clearing.
	p.payload = command.Data

	return p.response, p.err
}

func checkKeyImportCleared(t testing.TB, p *keyImportPeer) {
	t.Helper()

	if p.calls != 1 || len(p.payload) == 0 {
		t.Fatalf("import exchanges = %d, payload length = %d; want one nonempty payload", p.calls, len(p.payload))
	}

	for _, b := range p.payload {
		if b != 0 {
			t.Fatal("owned encoded key payload was not cleared after import returned")
		}
	}
}

func keyImportP256Fixture(t testing.TB) (*ecdsa.PrivateKey, protocol.AlgorithmAttributes, []byte) {
	t.Helper()

	scalar := [32]byte{31: 1}

	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar[:])
	if err != nil {
		t.Fatal(err)
	}

	point, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	material := slices.Concat(scalar[:], point)

	t.Cleanup(func() { clear(material) })

	attributes := protocol.AlgorithmAttributes{
		Algorithm: protocol.ECDSA, CurveOID: []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}, ImportFormat: 0xff,
	}

	return key, attributes, material
}
