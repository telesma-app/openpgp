package sm

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestIntegrationClientEmptyKeyContainerDeletion(t *testing.T) {
	for _, compatibility := range []bool{false, true} {
		t.Run(fmt.Sprintf("compatibility=%t", compatibility), func(t *testing.T) {
			p := newStaticPeer()
			channel := openStaticPeer(t, p, staticParameters(16))
			p.effect = func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				if command.INS == byte(protocol.GetChallenge) {
					return iso7816.Response{Data: make([]byte, 16), Status: 0x9000}, nil
				}

				if command.CLA != 0x0c || command.INS != byte(protocol.PutData) || command.P1 != 0 || command.P2 != 0xf4 ||
					len(command.Data) != 10 || command.Data[0] != 0x8e || command.Data[1] != 8 {
					t.Fatalf("protected empty F4 = %+v, want header and MAC without logical Le", command)
				}

				return iso7816.Response{Status: 0x9000}, nil
			}

			var options []client.Option
			if compatibility {
				options = append(options, client.WithEmptyPutDataLe())
			}

			err := client.NewClient(channel, options...).PutData(t.Context(), protocol.SMKeyContainerObject, nil)
			if compatibility {
				if !errors.Is(err, iso7816.ErrInvalidCommand) || len(p.requests) != 0 || !channel.isOpen() {
					t.Fatalf("compatibility deletion = %v, requests=%d, open=%t", err, len(p.requests), channel.isOpen())
				}
			} else if err != nil || len(p.requests) != 2 || channel.isOpen() || p.closeCalls != 1 {
				t.Fatalf("standard deletion = %v, requests=%d, open=%t, closes=%d", err, len(p.requests), channel.isOpen(), p.closeCalls)
			}
		})
	}
}
