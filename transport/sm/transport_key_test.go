package sm

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

func TestSuccessfulKeyDeletionClosesConnection(t *testing.T) {
	p := newStaticPeer()
	channel := openStaticPeer(t, p, staticParameters(16))
	p.effect = func(_ context.Context, request iso7816.Command) (iso7816.Response, error) {
		if request.INS == 0x84 {
			return iso7816.Response{Data: make([]byte, 16), Status: 0x9000}, nil
		}

		return iso7816.Response{Status: 0x9000}, nil
	}

	response, err := channel.Exchange(t.Context(), iso7816.Command{
		INS: 0xda, P2: 0xf4, Data: []byte{0xd1, 0, 0xd2, 0},
	})
	if err != nil || response.Status != 0x9000 || channel.isOpen() || p.closeCalls != 1 {
		t.Fatalf("key deletion = %+v, %v, closes=%d", response, err, p.closeCalls)
	}

	if _, err := channel.Exchange(t.Context(), staticReadCommand()); !errors.Is(err, io.ErrClosedPipe) || len(p.requests) != 2 {
		t.Fatalf("Exchange after key deletion = %v", err)
	}
}

func TestKeyContainerRejectsOuterTemplateBeforeChallenge(t *testing.T) {
	p := newStaticPeer()
	channel := openStaticPeer(t, p, staticParameters(16))
	command := keyRotationCommand(protocol.SMKeyContainerObject, rotatedKeys(16))
	command.Data = append([]byte{0xf4, byte(len(command.Data))}, command.Data...)
	requests := len(p.requests)

	_, err := channel.Exchange(t.Context(), command)
	if !errors.Is(err, iso7816.ErrInvalidCommand) || len(p.requests) != requests || p.closeCalls != 0 {
		t.Fatalf("outer key container = %v, requests=%d, closes=%d", err, len(p.requests), p.closeCalls)
	}
}

func TestKeyDeletionWithResponseRejectedBeforeChallenge(t *testing.T) {
	p := newStaticPeer()
	channel := openStaticPeer(t, p, staticParameters(16))
	requests := len(p.requests)

	_, err := channel.Exchange(t.Context(), iso7816.Command{
		INS: byte(protocol.PutData), P2: 0xf4, Data: []byte{0xd1, 0, 0xd2, 0}, Le: 256,
	})
	if !errors.Is(err, iso7816.ErrInvalidCommand) || len(p.requests) != requests || p.closeCalls != 0 {
		t.Fatalf("key deletion with Le = %v, requests=%d, closes=%d", err, len(p.requests), p.closeCalls)
	}
}
