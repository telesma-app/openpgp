package card

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport"
	"github.com/telesma-app/openpgp/transport/sm"
)

func secureMessagingApplication(capabilities []byte) []byte {
	data := bertlv.Append(nil, 0x4f, []byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 1, 0, 0, 0, 1, 0, 0})
	if capabilities != nil {
		data = bertlv.Append(data, 0x73, bertlv.Append(nil, 0xc0, capabilities))
	}

	return bertlv.Append(nil, 0x6e, data)
}

func secureMessagingParameters(keySize int) sm.Parameters {
	return sm.Parameters{
		Keys: sm.Keys{
			ENC: bytes.Repeat([]byte{0x11}, keySize),
			MAC: bytes.Repeat([]byte{0x22}, keySize),
		},
		Encoding: iso7816.EncodingShort,
	}
}

func TestOpenSecureMessagingDiscoversCapabilitiesAndOwnsConnection(t *testing.T) {
	for _, keySize := range []int{16, 32} {
		for _, embedded := range []bool{true, false} {
			for _, extended := range []bool{false, true} {
				t.Run(fmt.Sprintf("AES-%d/embedded=%t/extended=%t", keySize*8, embedded, extended), func(t *testing.T) {
					algorithm := byte(1)
					if keySize == 32 {
						algorithm = 2
					}

					capabilities := []byte{0xc0, algorithm, 0, 16, 0, 0, 0, 0, 0, 0}

					application := secureMessagingApplication(nil)
					if embedded {
						application = secureMessagingApplication(capabilities)
					}

					wantRequests := 1
					if !embedded {
						wantRequests = 2
					}

					encoding := iso7816.EncodingShort
					responseLength := uint32(256)

					var options []client.Option

					if extended {
						encoding = iso7816.EncodingExtended
						responseLength = 65536

						options = append(options, client.WithExtendedLength())
					}

					var requests, closes int

					connection := &exchangeTransport{
						exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
							requests++

							if command.INS == 0x20 {
								if command.CLA != 0x0c || command.P1 != 0 || command.P2 != 0x83 || command.Le != 256 ||
									command.Encoding != iso7816.EncodingShort || len(command.Data) != 29 {
									t.Fatalf("protected VERIFY = %+v", command)
								}

								return iso7816.Response{Status: 0x9000}, nil
							}

							commandEncoding := encoding
							if command.INS == 0x84 && requests == wantRequests+2 {
								commandEncoding = iso7816.EncodingShort
							}

							if command.CLA != 0 || command.Encoding != commandEncoding || command.P1 != 0 || len(command.Data) != 0 {
								t.Fatalf("command = %+v", command)
							}

							switch command.INS {
							case 0xca:
								if command.Le != responseLength {
									t.Fatalf("discovery Le = %d, want %d", command.Le, responseLength)
								}

								if requests == 1 && command.P2 == 0x6e {
									return iso7816.Response{Data: application, Status: 0x9000}, nil
								}

								if requests == 2 && !embedded && command.P2 == 0xc0 {
									return iso7816.Response{Data: capabilities, Status: 0x9000}, nil
								}
							case 0x84:
								if command.P2 == 0 && command.Le == 16 {
									return iso7816.Response{Data: bytes.Repeat([]byte{1}, 16), Status: 0x9000}, nil
								}
							}

							t.Fatalf("unexpected command = %+v", command)

							return iso7816.Response{}, nil
						},
						close: func() error { closes++; return nil },
					}

					device, err := OpenSecureMessaging(t.Context(), connection, secureMessagingParameters(keySize), options...)
					if err != nil {
						t.Fatal(err)
					}

					t.Cleanup(func() { _ = device.Close() })

					if requests != wantRequests || closes != 0 {
						t.Fatalf("OpenSecureMessaging sent %d commands and closed %d times", requests, closes)
					}

					challenge, err := device.GetChallenge(t.Context(), 16)
					if err != nil || !bytes.Equal(challenge, bytes.Repeat([]byte{1}, 16)) || requests != wantRequests+1 {
						t.Fatalf("GetChallenge = %x, %v; requests=%d", challenge, err, requests)
					}

					if err := device.Verify(t.Context(), protocol.PW3, []byte("admin password")); err != nil {
						t.Fatal(err)
					}

					if requests != wantRequests+3 {
						t.Fatalf("VERIFY requests = %d, want %d", requests, wantRequests+3)
					}

					for range 2 {
						if err := device.Close(); err != nil {
							t.Fatal(err)
						}
					}

					if closes != 1 {
						t.Fatalf("Close calls = %d, want 1", closes)
					}

					if _, err := device.GetChallenge(t.Context(), 16); !errors.Is(err, io.ErrClosedPipe) || requests != wantRequests+3 {
						t.Fatalf("GetChallenge after Close = %v; requests=%d", err, requests)
					}
				})
			}
		}
	}
}

func TestFailedOpenSecureMessagingPreservesCallerOwnership(t *testing.T) {
	for _, mode := range []string{
		"no SM", "proprietary", "SCP11b", "different AES", "malformed application",
		"malformed capabilities", "malformed fallback capabilities", "application I/O",
		"fallback I/O", "invalidated connection", "invalid parameters", "canceled",
	} {
		t.Run(mode, func(t *testing.T) {
			parameters := secureMessagingParameters(16)
			capabilities := []byte{0xc0, 1, 0, 16, 0, 0, 0, 0, 0, 0}
			wantRequests := 1

			var wantCause, applicationError, fallbackError error

			switch mode {
			case "no SM":
				capabilities[0] &^= 0x80
			case "proprietary":
				capabilities[1] = 0
			case "SCP11b":
				capabilities[1] = 3
			case "different AES":
				capabilities[1] = 2
			case "malformed capabilities", "malformed fallback capabilities":
				capabilities = capabilities[:9]
				wantCause = protocol.ErrInvalidResponse
			case "malformed application":
				wantCause = protocol.ErrInvalidResponse
			case "application I/O", "invalidated connection":
				wantCause = errors.New("application read failed")

				applicationError = wantCause
				if mode == "invalidated connection" {
					applicationError = &transport.DeviceInvalidatedError{Err: wantCause}
				}
			case "fallback I/O":
				wantCause = errors.New("capabilities read failed")
				fallbackError = wantCause
			case "invalid parameters":
				parameters.Encoding = iso7816.EncodingAuto
			case "canceled":
				wantCause = context.Canceled
				wantRequests = 0
			}

			application := secureMessagingApplication(capabilities)
			if mode == "malformed application" {
				application = []byte{0x6e, 0}
			}

			if mode == "malformed fallback capabilities" || mode == "fallback I/O" {
				application = secureMessagingApplication(nil)
				wantRequests = 2
			}

			var requests, closes int

			connection := &exchangeTransport{
				exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
					requests++

					if command.CLA != 0 || command.INS != 0xca || command.P1 != 0 {
						t.Fatalf("discovery command = %+v", command)
					}

					switch command.P2 {
					case 0x6e:
						return iso7816.Response{Data: application, Status: 0x9000}, applicationError
					case 0xc0:
						return iso7816.Response{Data: capabilities, Status: 0x9000}, fallbackError
					default:
						t.Fatalf("unexpected discovery command = %+v", command)
						return iso7816.Response{}, nil
					}
				},
				close: func() error { closes++; return nil },
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			if mode == "canceled" {
				cancel()
			}

			enc := bytes.Clone(parameters.Keys.ENC)
			mac := bytes.Clone(parameters.Keys.MAC)

			device, err := OpenSecureMessaging(ctx, connection, parameters)
			if device != nil || err == nil {
				t.Fatalf("OpenSecureMessaging = %v, %v", device, err)
			}

			if wantCause != nil && !errors.Is(err, wantCause) {
				t.Errorf("OpenSecureMessaging error = %v, want cause %v", err, wantCause)
			}

			if mode == "invalidated connection" {
				var invalidated *transport.DeviceInvalidatedError
				if !errors.As(err, &invalidated) {
					t.Errorf("OpenSecureMessaging error = %v, want DeviceInvalidatedError", err)
				}
			}

			if requests != wantRequests || closes != 0 {
				t.Errorf("OpenSecureMessaging sent %d commands and closed %d times; want %d commands and no Close", requests, closes, wantRequests)
			}

			if !bytes.Equal(parameters.Keys.ENC, enc) || !bytes.Equal(parameters.Keys.MAC, mac) {
				t.Error("failed OpenSecureMessaging changed caller keys")
			}
		})
	}
}
