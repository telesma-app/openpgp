package sm

import (
	"bytes"
	"context"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestIntegrationSelectDataUsesItsDefinedPlaintextCommand(t *testing.T) {
	p := newStaticPeer()
	channel := openStaticPeer(t, p, staticParameters(16))
	p.effect = func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
		if command.CLA != 0 || command.INS != 0xa5 || command.P1 != 1 || command.P2 != 4 ||
			!bytes.Equal(command.Data, []byte{0x60, 4, 0x5c, 2, 0x7f, 0x21}) {
			t.Fatalf("SELECT DATA = %+v", command)
		}

		return iso7816.Response{Status: 0x9000}, nil
	}

	err := client.NewClient(channel).SelectData(t.Context(), protocol.CardholderCertificateObject, 1)
	if err != nil {
		t.Fatal(err)
	}

	if len(p.requests) != 1 || !channel.isOpen() {
		t.Fatal("SELECT DATA requested a challenge or retired the connection")
	}
}
