package sm

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

func TestKeyReplacementUsesNewResponseKeys(t *testing.T) {
	rnd := [16]byte(decodeHex(t, "000102030405060708090a0b0c0d0e0f"))

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
					response, err = iso7816.ParseResponse(decodeHex(t,
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
	rnd := [16]byte(decodeHex(t, "000102030405060708090a0b0c0d0e0f"))

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
	rnd := [16]byte(decodeHex(t, "000102030405060708090a0b0c0d0e0f"))
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
