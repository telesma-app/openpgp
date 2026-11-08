package sm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport"
)

func TestNewWithoutIOCopiesKeys(t *testing.T) {
	for _, keySize := range []int{16, 32} {
		for _, encoding := range []iso7816.Encoding{iso7816.EncodingShort, iso7816.EncodingExtended} {
			p := newStaticPeer()
			parameters := staticParameters(keySize)
			parameters.Encoding = encoding
			channel := openStaticPeer(t, p, parameters)

			if len(p.requests) != 0 {
				t.Fatalf("New requests = %+v", p.requests)
			}

			if channel.session.encoding != encoding || channel.session.macLength != 8 {
				t.Fatalf("encoding/MAC length = %v/%d", channel.session.encoding, channel.session.macLength)
			}

			parameters.Keys.ENC[0] ^= 0xff

			parameters.Keys.MAC[0] ^= 0xff
			if channel.session.keys.ENC[0] != 0x11 || channel.session.keys.MAC[0] != 0x22 {
				t.Fatal("transport retained borrowed key slices")
			}
		}
	}
}

func TestSequentialCommandsUseFreshChallenges(t *testing.T) {
	for _, keySize := range []int{16, 32} {
		for _, encoding := range []iso7816.Encoding{iso7816.EncodingShort, iso7816.EncodingExtended} {
			p := newStaticPeer()
			parameters := staticParameters(keySize)
			parameters.Encoding = encoding
			channel := openStaticPeer(t, p, parameters)
			challengeNumber := byte(0)
			p.effect = func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				if command.INS == 0x84 {
					challengeNumber++
					return iso7816.Response{Data: bytes.Repeat([]byte{challengeNumber}, 16), Status: 0x9000}, nil
				}

				if command.CLA != 0x0c || command.INS != 0x20 || command.P2 != 0x83 || command.Encoding != encoding {
					t.Fatalf("protected command = %+v", command)
				}

				return iso7816.Response{Status: 0x9000}, nil
			}

			password := []byte("admin password")
			for range 3 {
				response, err := channel.Exchange(t.Context(), iso7816.Command{INS: 0x20, P2: 0x83, Data: password})
				if err != nil || response.Status != 0x9000 || len(response.Data) != 0 {
					t.Fatalf("Exchange = %+v, %v", response, err)
				}
			}

			if challengeNumber != 3 || len(p.requests) != 6 || !bytes.Equal(password, []byte("admin password")) {
				t.Fatalf("challenges=%d, requests=%d, password changed=%t", challengeNumber, len(p.requests), !bytes.Equal(password, []byte("admin password")))
			}

			if bytes.Equal(p.requests[1].Data, p.requests[3].Data) || bytes.Equal(p.requests[3].Data, p.requests[5].Data) {
				t.Fatal("new challenges did not change protected command data")
			}
		}
	}
}

func TestAuthenticatedApplicationErrorPreservesConnection(t *testing.T) {
	for _, keySize := range []int{16, 32} {
		for _, macLength := range []int{8, 16} {
			p := newStaticPeer()
			parameters := staticParameters(keySize)
			parameters.MACLength = macLength
			channel := openStaticPeer(t, p, parameters)
			rnd := [16]byte{1, 2, 3, 4}
			protectedCommands := 0
			p.effect = func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				if command.INS == 0x84 {
					return iso7816.Response{Data: rnd[:], Status: 0x9000}, nil
				}

				protectedCommands++
				if protectedCommands == 1 {
					return staticResponse(t, parameters.Keys, macLength, rnd, command.INS, nil, 0x6982), nil
				}

				return staticResponse(t, parameters.Keys, macLength, rnd, command.INS, []byte("object data"), 0x9000), nil
			}

			response, err := channel.Exchange(t.Context(), staticReadCommand())
			if err != nil || response.Status != 0x6982 || len(response.Data) != 0 || !channel.isOpen() {
				t.Fatalf("authenticated error = %+v, %v", response, err)
			}

			response, err = channel.Exchange(t.Context(), staticReadCommand())
			if err != nil || response.Status != 0x9000 || string(response.Data) != "object data" || p.closeCalls != 0 {
				t.Fatalf("Exchange after application error = %+v, %v", response, err)
			}
		}
	}
}

func TestCompletedResponseIgnoresLateCancellation(t *testing.T) {
	p := newStaticPeer()
	parameters := staticParameters(16)
	channel := openStaticPeer(t, p, parameters)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	rnd := [16]byte{3, 2, 1}
	p.effect = func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
		if command.INS == 0x84 {
			return iso7816.Response{Data: rnd[:], Status: 0x9000}, nil
		}

		response := staticResponse(t, parameters.Keys, 8, rnd, command.INS, []byte("completed"), 0x9000)

		cancel()

		return response, nil
	}

	response, err := channel.Exchange(ctx, staticReadCommand())
	if err != nil || string(response.Data) != "completed" || !channel.isOpen() {
		t.Fatalf("Exchange = %+v, %v", response, err)
	}
}

func TestFailedNewPreservesCallerOwnership(t *testing.T) {
	for _, mode := range []string{"encoding", "MAC length", "AES-192", "unequal keys"} {
		t.Run(mode, func(t *testing.T) {
			p := newStaticPeer()
			parameters := staticParameters(16)

			switch mode {
			case "encoding":
				parameters.Encoding = iso7816.EncodingAuto
			case "MAC length":
				parameters.MACLength = 7
			case "AES-192":
				parameters.Keys = staticParameters(24).Keys
			case "unequal keys":
				parameters.Keys.MAC = bytes.Repeat([]byte{0x22}, 32)
			}

			enc := slices.Clone(parameters.Keys.ENC)
			mac := slices.Clone(parameters.Keys.MAC)

			channel, err := New(p, parameters)
			if channel != nil || err == nil {
				t.Fatalf("New = %v, %v", channel, err)
			}

			if p.closeCalls != 0 || len(p.requests) != 0 {
				t.Fatalf("New sent %d commands and closed %d times", len(p.requests), p.closeCalls)
			}

			if !bytes.Equal(parameters.Keys.ENC, enc) || !bytes.Equal(parameters.Keys.MAC, mac) {
				t.Fatal("failed New changed caller keys")
			}
		})
	}
}

func TestExchangeRejectsUnsupportedCommandsBeforeChallenge(t *testing.T) {
	p := newStaticPeer()

	channel := openStaticPeer(t, p, staticParameters(16))
	for _, command := range []iso7816.Command{
		{INS: 0xff},
		{INS: 0x00},
		{CLA: 0x0c, INS: byte(protocol.GetData), Le: 256},
	} {
		if _, err := channel.Exchange(t.Context(), command); !errors.Is(err, iso7816.ErrInvalidCommand) {
			t.Fatalf("Exchange %+v = %v", command, err)
		}
	}

	if len(p.requests) != 0 || !channel.isOpen() {
		t.Fatal("unsupported command performed I/O or retired the connection")
	}
}

func TestChallengeFailureDoesNotSendProtectedCommand(t *testing.T) {
	for _, mode := range []string{"rejected", "short", "long", "I/O", "interrupted"} {
		t.Run(mode, func(t *testing.T) {
			p := newStaticPeer()
			channel := openStaticPeer(t, p, staticParameters(16))
			cause := errors.New("challenge I/O failed")
			p.effect = func(context.Context, iso7816.Command) (iso7816.Response, error) {
				switch mode {
				case "rejected":
					return iso7816.Response{Status: 0x6a81}, nil
				case "short":
					return iso7816.Response{Data: make([]byte, 15), Status: 0x9000}, nil
				case "long":
					return iso7816.Response{Data: make([]byte, 17), Status: 0x9000}, nil
				case "interrupted":
					return iso7816.Response{}, &transport.DeviceInvalidatedError{Err: context.Canceled}
				default:
					return iso7816.Response{}, cause
				}
			}

			response, err := channel.Exchange(t.Context(), staticReadCommand())
			if err == nil || len(response.Data) != 0 || len(p.requests) != 1 {
				t.Fatalf("Exchange = %+v, %v; requests=%d", response, err, len(p.requests))
			}

			request := p.requests[0]
			if request.CLA != 0 || request.INS != 0x84 || request.Le != 16 || request.Encoding != iso7816.EncodingShort {
				t.Fatalf("challenge = %+v", request)
			}

			var invalidated *transport.DeviceInvalidatedError
			if mode == "rejected" {
				var apduError *iso7816.APDUError
				if !errors.As(err, &apduError) || apduError.StatusWord() != 0x6a81 || errors.As(err, &invalidated) || p.closeCalls != 0 {
					t.Fatalf("rejected challenge = %v, closes=%d", err, p.closeCalls)
				}
			} else if !errors.As(err, &invalidated) || p.closeCalls != 1 || channel.isOpen() {
				t.Fatalf("invalid challenge = %v, closes=%d", err, p.closeCalls)
			}
		})
	}
}

func TestCancellationBeforeProtectedIOPreservesConnection(t *testing.T) {
	for _, stage := range []string{"before challenge", "after challenge", "before protected command"} {
		t.Run(stage, func(t *testing.T) {
			p := newStaticPeer()
			channel := openStaticPeer(t, p, staticParameters(16))

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			p.effect = func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				if command.INS == 0x84 {
					if stage == "after challenge" {
						cancel()
					}

					return iso7816.Response{Data: make([]byte, 16), Status: 0x9000}, nil
				}

				cancel()

				return iso7816.Response{}, ctx.Err()
			}

			if stage == "before challenge" {
				cancel()
			}

			_, err := channel.Exchange(ctx, staticReadCommand())

			var invalidated *transport.DeviceInvalidatedError
			if !errors.Is(err, context.Canceled) || errors.As(err, &invalidated) || p.closeCalls != 0 || !channel.isOpen() {
				t.Fatalf("Exchange = %v, closes=%d", err, p.closeCalls)
			}

			wantRequests := 0

			switch stage {
			case "after challenge":
				wantRequests = 1
			case "before protected command":
				wantRequests = 2
			}

			if len(p.requests) != wantRequests {
				t.Fatalf("requests=%d, want %d", len(p.requests), wantRequests)
			}
		})
	}
}

func TestProtectedResponseFailureInvalidatesConnection(t *testing.T) {
	for _, mode := range []string{"bare status", "bad MAC", "I/O", "interrupted"} {
		t.Run(mode, func(t *testing.T) {
			p := newStaticPeer()
			channel := openStaticPeer(t, p, staticParameters(16))
			cause := errors.New("protected response lost")
			p.effect = func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				if command.INS == 0x84 {
					return iso7816.Response{Data: make([]byte, 16), Status: 0x9000}, nil
				}

				switch mode {
				case "bare status":
					return iso7816.Response{Status: 0x6988}, nil
				case "bad MAC":
					return iso7816.Response{Data: []byte{0x99, 2, 0x90, 0, 0x8e, 8, 0, 0, 0, 0, 0, 0, 0, 0}, Status: 0x9000}, nil
				case "interrupted":
					return iso7816.Response{}, &transport.DeviceInvalidatedError{Err: context.Canceled}
				default:
					return iso7816.Response{}, cause
				}
			}

			response, err := channel.Exchange(t.Context(), staticReadCommand())

			var invalidated *transport.DeviceInvalidatedError
			if !errors.As(err, &invalidated) || len(response.Data) != 0 || p.closeCalls != 1 || channel.isOpen() {
				t.Fatalf("Exchange = %+v, %v, closes=%d", response, err, p.closeCalls)
			}

			if mode == "bad MAC" && !errors.Is(err, ErrAuthentication) {
				t.Fatalf("bad MAC = %v", err)
			}

			if mode == "I/O" && !errors.Is(err, cause) {
				t.Fatalf("I/O error = %v", err)
			}

			if len(channel.session.keys.ENC) != 0 || len(channel.session.keys.MAC) != 0 || len(p.requests) != 2 {
				t.Fatal("invalid response retained keys or sent another command")
			}

			if _, err := channel.Exchange(t.Context(), staticReadCommand()); !errors.Is(err, io.ErrClosedPipe) || len(p.requests) != 2 {
				t.Fatalf("Exchange after invalidation = %v", err)
			}
		})
	}
}

func TestQueuedExchangeCancellationPreservesActiveConnection(t *testing.T) {
	for _, stage := range []string{"challenge", "protected command"} {
		for _, test := range []struct {
			name     string
			deadline bool
			want     error
		}{
			{name: "canceled", want: context.Canceled},
			{name: "deadline", deadline: true, want: context.DeadlineExceeded},
		} {
			t.Run(stage+"/"+test.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					p := newStaticPeer()
					parameters := staticParameters(16)
					channel := openStaticPeer(t, p, parameters)
					release := make(chan struct{}, 1)

					defer func() {
						close(release)

						_ = channel.Close()

						synctest.Wait()
					}()

					blockedInstruction := byte(0x84)
					wantRequests := 1

					if stage == "protected command" {
						blockedInstruction = 0xca
						wantRequests = 2
					}

					rnd := [16]byte{1, 2, 3}
					blockNext := true
					p.effect = func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
						if blockNext && command.INS == blockedInstruction {
							blockNext = false

							select {
							case <-release:
							case <-p.closed:
								return iso7816.Response{}, io.ErrClosedPipe
							}
						}

						if command.INS == 0x84 {
							return iso7816.Response{Data: rnd[:], Status: 0x9000}, nil
						}

						return staticResponse(t, parameters.Keys, 8, rnd, command.INS, []byte("object data"), 0x9000), nil
					}

					type result struct {
						response iso7816.Response
						err      error
					}

					active := make(chan result, 1)

					go func() {
						response, err := channel.Exchange(t.Context(), staticReadCommand())
						active <- result{response: response, err: err}
					}()

					synctest.Wait()

					if len(p.requests) != wantRequests || blockNext {
						t.Fatalf("active requests=%d, block pending=%t; want blocked %s", len(p.requests), blockNext, stage)
					}

					var (
						ctx    context.Context
						cancel context.CancelFunc
					)

					if test.deadline {
						ctx, cancel = context.WithTimeout(t.Context(), time.Second)
					} else {
						ctx, cancel = context.WithCancel(t.Context())
					}

					defer cancel()

					queued := make(chan result, 1)

					go func() {
						response, err := channel.Exchange(ctx, staticReadCommand())
						queued <- result{response: response, err: err}
					}()

					synctest.Wait()

					select {
					case got := <-queued:
						t.Fatalf("queued Exchange returned before cancellation: %+v, %v", got.response, got.err)
					default:
					}

					if test.deadline {
						time.Sleep(time.Second) // Advance the synctest clock after the waiter is blocked.
					} else {
						cancel()
					}

					synctest.Wait()

					select {
					case got := <-queued:
						var invalidated *transport.DeviceInvalidatedError
						if !errors.Is(got.err, test.want) || errors.As(got.err, &invalidated) || got.response.Data != nil || got.response.Status != 0 {
							t.Errorf("queued Exchange = %+v, %v; want empty response and %v without invalidation", got.response, got.err, test.want)
						}
					default:
						t.Fatal("queued Exchange did not finish after cancellation while the active exchange remained blocked")
					}

					if len(p.requests) != wantRequests || p.closeCalls != 0 || !channel.isOpen() {
						t.Fatalf("queued cancellation sent %d requests and closed %d times", len(p.requests), p.closeCalls)
					}

					select {
					case got := <-active:
						t.Fatalf("active Exchange returned before release: %+v, %v", got.response, got.err)
					default:
					}

					release <- struct{}{}

					synctest.Wait()

					select {
					case got := <-active:
						if got.err != nil || got.response.Status != 0x9000 || string(got.response.Data) != "object data" {
							t.Errorf("active Exchange = %+v, %v; want successful object read", got.response, got.err)
						}
					default:
						t.Fatal("active Exchange did not finish after release")
					}

					response, err := channel.Exchange(t.Context(), staticReadCommand())
					if err != nil || response.Status != 0x9000 || string(response.Data) != "object data" || len(p.requests) != 4 || p.closeCalls != 0 {
						t.Errorf("Exchange after cancellation = %+v, %v; requests=%d closes=%d", response, err, len(p.requests), p.closeCalls)
					}
				})
			})
		}
	}
}

func TestCloseInterruptsIOAndReleasesWaiters(t *testing.T) {
	for _, stage := range []string{"challenge", "protected command"} {
		t.Run(stage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := newStaticPeer()
				channel := openStaticPeer(t, p, staticParameters(16))
				p.effect = func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
					if stage == "protected command" && command.INS == 0x84 {
						return iso7816.Response{Data: make([]byte, 16), Status: 0x9000}, nil
					}

					<-p.closed

					return iso7816.Response{}, io.ErrClosedPipe
				}

				active := make(chan error, 1)

				go func() { _, err := channel.Exchange(t.Context(), staticReadCommand()); active <- err }()

				synctest.Wait()

				queued := make(chan error, 1)

				go func() { _, err := channel.Exchange(t.Context(), staticReadCommand()); queued <- err }()

				synctest.Wait()

				if err := channel.Close(); err != nil {
					t.Fatal(err)
				}

				synctest.Wait()

				if !errors.Is(<-queued, io.ErrClosedPipe) || !errors.Is(<-active, io.ErrClosedPipe) {
					t.Fatal("Close did not release active and queued exchanges")
				}

				if p.closeCalls != 1 || channel.isOpen() || len(channel.session.keys.ENC) != 0 || len(channel.session.keys.MAC) != 0 {
					t.Fatal("Close did not retire the connection and owned keys once")
				}
			})
		})
	}
}

func TestCloseClearsOwnedKeysAndPreservesCallerKeys(t *testing.T) {
	p := newStaticPeer()
	parameters := staticParameters(16)
	channel := openStaticPeer(t, p, parameters)
	enc := channel.session.keys.ENC
	mac := channel.session.keys.MAC

	p.closeErr = errors.New("close failed")
	for range 2 {
		if err := channel.Close(); !errors.Is(err, p.closeErr) {
			t.Fatal(err)
		}
	}

	if p.closeCalls != 1 || !bytes.Equal(enc, make([]byte, 16)) || !bytes.Equal(mac, make([]byte, 16)) {
		t.Fatal("Close repeated or retained owned key bytes")
	}

	if !bytes.Equal(parameters.Keys.ENC, bytes.Repeat([]byte{0x11}, 16)) || !bytes.Equal(parameters.Keys.MAC, bytes.Repeat([]byte{0x22}, 16)) {
		t.Fatal("Close changed caller keys")
	}

	if _, err := channel.Exchange(t.Context(), staticReadCommand()); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Exchange after Close = %v", err)
	}
}
