package card

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

func TestUserInteractionFlagOperations(t *testing.T) {
	var commands [][]byte

	d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
		raw, err := command.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}

		commands = append(commands, raw)

		if command.INS == 0xca {
			return success([]byte{
				0x4f, 0x10, 0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 6, 0, 0, 0, 1, 0, 0,
				0x73, 4, 0xd7, 2, 0x7f, 0x81,
			}), nil
		}

		return success(nil), nil
	}})

	t.Cleanup(func() { _ = d.Close() })

	flag, err := d.GetUserInteractionFlag(t.Context(), protocol.DecryptionUIFObject)
	if err != nil || flag.State != 0x7f || flag.Features != 0x81 {
		t.Fatalf("flag = %+v, %v", flag, err)
	}

	if err := d.PutUserInteractionFlag(t.Context(), protocol.DecryptionUIFObject, flag, nil); err != nil {
		t.Fatal(err)
	}

	want := [][]byte{{0, 0xca, 0, 0x6e, 0}, {0, 0xda, 0, 0xd7, 2, 0x7f, 0x81}}
	if !reflect.DeepEqual(commands, want) {
		t.Errorf("commands = %x, want %x", commands, want)
	}
}

func TestPutUserInteractionFlagAuthentication(t *testing.T) {
	cause := errors.New("password source failed")
	verify := []byte{0, 0x20, 0, 0x83, 11, 'e', 'n', 'c', 'o', 'd', 'e', 'd', ' ', 'P', 'W', '3'}
	put := []byte{0, 0xda, 0, 0xd8, 2, 1, 0x10}

	for _, test := range []struct {
		name         string
		sourceError  error
		verifyStatus iso7816.StatusWord
		commands     [][]byte
	}{
		{name: "source error", sourceError: cause},
		{name: "wrong PW3", verifyStatus: 0x63c2, commands: [][]byte{verify}},
		{name: "PW3 and write", verifyStatus: 0x9000, commands: [][]byte{verify, put}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var (
				commands    [][]byte
				sourceCalls int
			)

			password := []byte("encoded PW3")
			d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				raw, err := command.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}

				commands = append(commands, raw)

				if command.INS == 0x20 {
					return iso7816.Response{Status: test.verifyStatus}, nil
				}

				return success(nil), nil
			}})

			t.Cleanup(func() { _ = d.Close() })

			flag := protocol.UserInteractionFlag{State: protocol.UIFEnabled, Features: protocol.GeneralFeatureKeypad}
			err := d.PutUserInteractionFlag(t.Context(), protocol.AuthenticationUIFObject, flag, func(context.Context) ([]byte, error) {
				sourceCalls++

				return password, test.sourceError
			})

			if test.sourceError != nil {
				if !errors.Is(err, test.sourceError) {
					t.Errorf("error = %v, want %v", err, test.sourceError)
				}
			} else if test.verifyStatus == 0x63c2 {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != 0x63c2 {
					t.Errorf("error = %v, want PW3 rejection 63c2", err)
				}
			} else if err != nil {
				t.Error(err)
			}

			if !reflect.DeepEqual(commands, test.commands) || sourceCalls != 1 {
				t.Errorf("commands = %x, source calls = %d; want %x and one source call", commands, sourceCalls, test.commands)
			}

			if test.sourceError == nil {
				if !bytes.Equal(password, make([]byte, len(password))) {
					t.Error("transferred password was not cleared")
				}
			} else if string(password) != "encoded PW3" {
				t.Error("failed source's password was changed")
			}
		})
	}
}
