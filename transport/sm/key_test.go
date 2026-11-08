package sm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestKeyReplacementUsesNewResponseKeys(t *testing.T) {
	rnd := [16]byte(recordHex(t, "000102030405060708090a0b0c0d0e0f"))

	for _, size := range []int{16, 32} {
		for _, object := range []protocol.Object{protocol.SMKeyENCObject, protocol.SMKeyMACObject, protocol.SMKeyContainerObject} {
			t.Run(fmt.Sprintf("AES%d/%02x", size*8, object), func(t *testing.T) {
				oldKeys := recordKeys(size)

				session, err := newRecordSession(oldKeys, iso7816.EncodingShort, 8)
				if err != nil {
					t.Fatal(err)
				}

				t.Cleanup(session.clear)

				next := rotatedKeys(size)
				command := keyRotationCommand(object, next)
				originalData := bytes.Clone(command.Data)
				responseKeys := next

				switch object {
				case protocol.SMKeyENCObject:
					responseKeys.MAC = oldKeys.MAC
				case protocol.SMKeyMACObject:
					responseKeys.ENC = oldKeys.ENC
				}

				var response iso7816.Response

				if size == 16 && object == protocol.SMKeyContainerObject {
					// Independently generated with OpenSSL 3.5.9 AES-128-CBC
					// (-nopad) and CMAC. ENC=40..4f, MAC=60..6f, RND=00..0f.
					// CMAC receives AES_MAC^-1(RND) followed by the ISO-padded
					// response DOs, initializing its state to RND before them.
					response, err = iso7816.ParseResponse(recordHex(t,
						"8711011381cf3ab1382eb4652160ccf7703af4990290008e0806cbcb8d41fdabb59000"))
					if err != nil {
						t.Fatal(err)
					}
				} else {
					response = staticResponse(t, responseKeys, 8, rnd, command.INS, []byte("rotated"), 0x9000)
				}

				plaintext, err := session.unprotect(command, response, rnd)
				if err != nil || plaintext.Status != 0x9000 || string(plaintext.Data) != "rotated" {
					t.Fatalf("key replacement response = %+v, %v", plaintext, err)
				}

				read := staticReadCommand()
				response = staticResponse(t, responseKeys, 8, rnd, read.INS, []byte("new keys committed"), 0x9000)

				plaintext, err = session.unprotect(read, response, rnd)
				if err != nil || string(plaintext.Data) != "new keys committed" {
					t.Fatalf("response after key replacement = %+v, %v", plaintext, err)
				}

				if !bytes.Equal(command.Data, originalData) {
					t.Error("key replacement changed borrowed command data")
				}

				if !bytes.Equal(oldKeys.ENC, recordKeys(size).ENC) || !bytes.Equal(oldKeys.MAC, recordKeys(size).MAC) {
					t.Error("key replacement cleared caller-owned original keys")
				}
			})
		}
	}
}

func TestKeyReplacementRejectionKeepsOldKeys(t *testing.T) {
	rnd := [16]byte(recordHex(t, "000102030405060708090a0b0c0d0e0f"))

	for _, object := range []protocol.Object{protocol.SMKeyENCObject, protocol.SMKeyMACObject, protocol.SMKeyContainerObject} {
		t.Run(fmt.Sprintf("%02x", object), func(t *testing.T) {
			keys := recordKeys(16)

			session, err := newRecordSession(keys, iso7816.EncodingShort, 8)
			if err != nil {
				t.Fatal(err)
			}

			t.Cleanup(session.clear)

			command := keyRotationCommand(object, rotatedKeys(16))
			response := staticResponse(t, keys, 8, rnd, command.INS, []byte("rejected"), 0x6982)

			plaintext, err := session.unprotect(command, response, rnd)
			if err != nil || plaintext.Status != 0x6982 || string(plaintext.Data) != "rejected" {
				t.Fatalf("key replacement rejection = %+v, %v", plaintext, err)
			}

			read := staticReadCommand()
			response = staticResponse(t, keys, 8, rnd, read.INS, []byte("old keys retained"), 0x9000)

			plaintext, err = session.unprotect(read, response, rnd)
			if err != nil || string(plaintext.Data) != "old keys retained" {
				t.Fatalf("response after rejected key replacement = %+v, %v", plaintext, err)
			}
		})
	}
}

func TestKeyReplacementTamperingDoesNotCommit(t *testing.T) {
	keys := recordKeys(16)

	session, err := newRecordSession(keys, iso7816.EncodingShort, 8)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(session.clear)
	rnd := [16]byte(recordHex(t, "000102030405060708090a0b0c0d0e0f"))
	next := rotatedKeys(16)
	command := keyRotationCommand(protocol.SMKeyContainerObject, next)
	originalData := bytes.Clone(command.Data)
	response := staticResponse(t, next, 8, rnd, command.INS, []byte("untrusted"), 0x9000)
	response.Data[len(response.Data)-1] ^= 1

	plaintext, err := session.unprotect(command, response, rnd)
	if !errors.Is(err, ErrInvalidResponse) || !errors.Is(err, ErrAuthentication) || plaintext.Data != nil {
		t.Fatalf("tampered key replacement response = %+v, %v", plaintext, err)
	}

	read := staticReadCommand()
	response = staticResponse(t, keys, 8, rnd, read.INS, []byte("old keys retained"), 0x9000)

	plaintext, err = session.unprotect(read, response, rnd)
	if err != nil || string(plaintext.Data) != "old keys retained" {
		t.Fatalf("session after invalid key replacement response = %+v, %v", plaintext, err)
	}

	if !bytes.Equal(command.Data, originalData) {
		t.Error("invalid key replacement response cleared borrowed replacement keys")
	}
}

func TestClientEmptyKeyContainerDeletion(t *testing.T) {
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

func TestKeyContainerDeletionClearsSession(t *testing.T) {
	session, err := newRecordSession(recordKeys(16), iso7816.EncodingShort, 8)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(session.clear)
	ownedKeys := session.keys
	command := iso7816.Command{INS: byte(protocol.PutData), P2: 0xf4, Data: []byte{0xd1, 0, 0xd2, 0}}
	rnd := [16]byte{}

	response, err := session.unprotect(command, iso7816.Response{Status: 0x9000}, rnd)
	if err != nil || response.Status != 0x9000 || response.Data != nil {
		t.Fatalf("key deletion = %+v, %v", response, err)
	}

	if len(session.keys.ENC) != 0 || len(session.keys.MAC) != 0 {
		t.Error("key deletion retained session keys")
	}

	if !bytes.Equal(ownedKeys.ENC, make([]byte, 16)) || !bytes.Equal(ownedKeys.MAC, make([]byte, 16)) {
		t.Error("key deletion did not clear owned key material")
	}

	if !bytes.Equal(command.Data, []byte{0xd1, 0, 0xd2, 0}) {
		t.Error("key deletion changed borrowed command data")
	}
}

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

func rotatedKeys(size int) Keys {
	keys := recordKeys(size)
	for i := range size {
		keys.ENC[i] ^= 0x40
		keys.MAC[i] ^= 0x40
	}

	return keys
}

func keyRotationCommand(object protocol.Object, keys Keys) iso7816.Command {
	command := iso7816.Command{INS: byte(protocol.PutData), P2: byte(object), Le: 256}
	switch object {
	case protocol.SMKeyENCObject:
		command.Data = keys.ENC
	case protocol.SMKeyMACObject:
		command.Data = keys.MAC
	case protocol.SMKeyContainerObject:
		command.Data = append([]byte{0xd1, byte(len(keys.ENC))}, keys.ENC...)
		command.Data = append(command.Data, 0xd2, byte(len(keys.MAC)))
		command.Data = append(command.Data, keys.MAC...)
	default:
		panic("unexpected key object")
	}

	return command
}
