package sm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport"
)

func TestIntegrationOperationalLifecycleCommandsPreserveSecureMessaging(t *testing.T) {
	for _, test := range []struct {
		name        string
		instruction protocol.Instruction
		status      iso7816.StatusWord
	}{
		{name: "activation succeeds", instruction: protocol.ActivateFile, status: 0x9000},
		{name: "activation rejected", instruction: protocol.ActivateFile, status: 0x6982},
		{name: "termination rejected", instruction: protocol.TerminateDF, status: 0x6982},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := newStaticPeer()
			parameters := staticParameters(16)
			channel := openStaticPeer(t, p, parameters)
			rnd := [16]byte{}
			p.effect = func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				if command.INS == byte(protocol.GetChallenge) {
					if command.CLA != 0 || command.Le != 16 {
						t.Fatalf("GET CHALLENGE = %+v", command)
					}

					return iso7816.Response{Data: rnd[:], Status: 0x9000}, nil
				}

				if command.CLA != 0x0c {
					t.Fatalf("unprotected command after lifecycle operation: %+v", command)
				}

				switch command.INS {
				case byte(test.instruction):
					if len(command.Data) != 10 || command.Data[0] != 0x8e || command.Data[1] != 8 {
						t.Fatalf("protected lifecycle command = %+v", command)
					}

					return iso7816.Response{Status: test.status}, nil
				case byte(protocol.GetData):
					return staticResponse(t, parameters.Keys, 8, rnd, command.INS, []byte{0x42}, 0x9000), nil
				default:
					t.Fatalf("unexpected command: %+v", command)
					return iso7816.Response{}, nil
				}
			}

			response, err := channel.Exchange(t.Context(), iso7816.Command{INS: byte(test.instruction)})
			if err != nil || response.Status != test.status {
				t.Fatalf("lifecycle response = %+v, %v", response, err)
			}

			data, err := client.NewClient(channel).GetData(t.Context(), protocol.ApplicationRelatedDataObject)
			if err != nil || !bytes.Equal(data, []byte{0x42}) {
				t.Fatalf("protected GET DATA after lifecycle command = %x, %v", data, err)
			}

			if len(p.requests) != 4 || p.closeCalls != 0 || !channel.isOpen() ||
				!bytes.Equal(channel.session.keys.ENC, parameters.Keys.ENC) ||
				!bytes.Equal(channel.session.keys.MAC, parameters.Keys.MAC) {
				t.Fatalf("lifecycle command changed secure connection: requests=%d, closes=%d", len(p.requests), p.closeCalls)
			}
		})
	}
}

func TestIntegrationActivateTerminatedApplicationWithoutReconnect(t *testing.T) {
	for _, establish := range []string{"TERMINATE DF", "SELECT 6285"} {
		for _, rejectFirst := range []bool{false, true} {
			name := establish
			if rejectFirst {
				name += "/activation rejected once"
			}

			t.Run(name, func(t *testing.T) {
				p := newStaticPeer()
				channel := openStaticPeer(t, p, staticParameters(16))
				ownedKeys := channel.session.keys
				terminated := false
				activationCalls := 0
				p.effect = func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
					switch command.INS {
					case byte(protocol.GetChallenge):
						if terminated || command.CLA != 0 || command.Le != 16 {
							t.Fatalf("GET CHALLENGE in initialization state: %+v", command)
						}

						return iso7816.Response{Data: make([]byte, 16), Status: 0x9000}, nil
					case byte(protocol.TerminateDF):
						if command.CLA != 0x0c || len(command.Data) != 10 {
							t.Fatalf("TERMINATE DF = %+v", command)
						}

						terminated = true

						return iso7816.Response{Status: 0x9000}, nil
					case byte(protocol.Select):
						if command.CLA != 0 {
							t.Fatalf("SELECT = %+v", command)
						}

						terminated = true

						return iso7816.Response{Status: 0x6285}, nil
					case byte(protocol.ActivateFile):
						if !terminated || command.CLA != 0 || command.P1 != 0 || command.P2 != 0 ||
							len(command.Data) != 0 || command.Le != 0 {
							t.Fatalf("ACTIVATE FILE = %+v", command)
						}

						activationCalls++
						if rejectFirst && activationCalls == 1 {
							return iso7816.Response{Status: 0x6985}, nil
						}

						return iso7816.Response{Status: 0x9000}, nil
					default:
						t.Fatalf("unexpected command: %+v", command)
						return iso7816.Response{}, nil
					}
				}
				c := client.NewClient(channel)

				if establish == "TERMINATE DF" {
					if err := c.TerminateDF(t.Context()); err != nil {
						t.Fatal(err)
					}
				} else {
					err := c.Select(t.Context())

					var apduError *iso7816.APDUError
					if !errors.As(err, &apduError) || apduError.StatusWord() != 0x6285 {
						t.Fatalf("SELECT = %v, want status 6285", err)
					}
				}

				if p.closeCalls != 0 || !channel.isOpen() || len(channel.session.keys.ENC) != 16 {
					t.Fatal("termination retired the connection before activation")
				}

				if rejectFirst {
					err := c.ActivateFile(t.Context())

					var apduError *iso7816.APDUError
					if !errors.As(err, &apduError) || apduError.StatusWord() != 0x6985 {
						t.Fatalf("rejected ACTIVATE FILE = %v, want status 6985", err)
					}

					if p.closeCalls != 0 || !channel.isOpen() || len(channel.session.keys.ENC) != 16 {
						t.Fatal("rejected activation retired the connection")
					}
				}

				if err := c.ActivateFile(t.Context()); err != nil {
					t.Fatal(err)
				}

				wantRequests := 3
				if establish == "SELECT 6285" {
					wantRequests--
				}

				if rejectFirst {
					wantRequests++
				}

				if len(p.requests) != wantRequests || p.closeCalls != 1 || channel.isOpen() ||
					len(channel.session.keys.ENC) != 0 || len(channel.session.keys.MAC) != 0 ||
					!bytes.Equal(ownedKeys.ENC, make([]byte, 16)) || !bytes.Equal(ownedKeys.MAC, make([]byte, 16)) {
					t.Fatalf("activation retained connection or keys: requests=%d, closes=%d", len(p.requests), p.closeCalls)
				}

				if _, err := c.GetData(t.Context(), protocol.ApplicationRelatedDataObject); !errors.Is(err, io.ErrClosedPipe) || len(p.requests) != wantRequests {
					t.Fatalf("GET DATA after reset = %v, requests=%d", err, len(p.requests))
				}
			})
		}
	}
}

func TestIntegrationMalformedActivationResponseInvalidatesConnection(t *testing.T) {
	p := newStaticPeer()
	channel := openStaticPeer(t, p, staticParameters(16))
	p.effect = func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
		switch command.INS {
		case byte(protocol.GetChallenge):
			return iso7816.Response{Data: make([]byte, 16), Status: 0x9000}, nil
		case byte(protocol.TerminateDF):
			return iso7816.Response{Status: 0x9000}, nil
		case byte(protocol.ActivateFile):
			if command.CLA != 0 {
				t.Fatalf("ACTIVATE FILE = %+v", command)
			}

			return iso7816.Response{Data: []byte{1}, Status: 0x9000}, nil
		default:
			t.Fatalf("unexpected command: %+v", command)
			return iso7816.Response{}, nil
		}
	}

	c := client.NewClient(channel)
	if err := c.TerminateDF(t.Context()); err != nil {
		t.Fatal(err)
	}

	err := c.ActivateFile(t.Context())

	var invalidated *transport.DeviceInvalidatedError
	if !errors.Is(err, ErrInvalidResponse) || !errors.As(err, &invalidated) ||
		p.closeCalls != 1 || channel.isOpen() || len(channel.session.keys.ENC) != 0 || len(p.requests) != 3 {
		t.Fatalf("malformed activation response = %v, requests=%d, closes=%d", err, len(p.requests), p.closeCalls)
	}
}
