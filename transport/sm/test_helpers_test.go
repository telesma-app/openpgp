package sm

import (
	"bytes"
	"context"
	"crypto/aes"
	"encoding/hex"
	"slices"
	"sync"
	"testing"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

type staticPeer struct {
	requests   []iso7816.Command
	effect     func(context.Context, iso7816.Command) (iso7816.Response, error)
	closed     chan struct{}
	closeOnce  sync.Once
	closeCalls int
	closeErr   error
}

func newStaticPeer() *staticPeer {
	return &staticPeer{closed: make(chan struct{})}
}

func staticParameters(keySize int) Parameters {
	return Parameters{
		Keys:     Keys{ENC: bytes.Repeat([]byte{0x11}, keySize), MAC: bytes.Repeat([]byte{0x22}, keySize)},
		Encoding: iso7816.EncodingShort,
	}
}

func (p *staticPeer) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	if err := ctx.Err(); err != nil {
		return iso7816.Response{}, err
	}

	request := command
	request.Data = slices.Clone(command.Data)
	p.requests = append(p.requests, request)

	return p.effect(ctx, command)
}

func (p *staticPeer) Close() error {
	p.closeCalls++
	p.closeOnce.Do(func() { close(p.closed) })

	return p.closeErr
}

func openStaticPeer(t testing.TB, p *staticPeer, parameters Parameters) *Transport {
	t.Helper()

	channel, err := New(p, parameters)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = channel.Close() })

	return channel
}

func staticReadCommand() iso7816.Command {
	return iso7816.Command{INS: byte(protocol.GetData), P2: 0x6e, Le: 256}
}

// staticResponse tests workflows; record tests check independent wire vectors.
func staticResponse(
	t testing.TB,
	keys Keys,
	macLength int,
	rnd [16]byte,
	instruction byte,
	plaintext []byte,
	status iso7816.StatusWord,
) iso7816.Response {
	t.Helper()

	enc, err := aes.NewCipher(keys.ENC)
	if err != nil {
		t.Fatal(err)
	}

	mac, err := aes.NewCipher(keys.MAC)
	if err != nil {
		t.Fatal(err)
	}

	var data []byte

	if len(plaintext) != 0 {
		encrypted := encrypt(enc, rnd, plaintext)
		if instruction&1 == 0 {
			data = bertlv.Append(nil, 0x87, append([]byte{1}, encrypted...))
		} else {
			data = bertlv.Append(nil, 0x85, encrypted)
		}
	}

	data = append(data, 0x99, 2, status.SW1(), status.SW2())

	padded := pad(data)
	defer clear(padded)

	checksum := cmac(mac, rnd, padded)
	data = bertlv.Append(data, 0x8e, checksum[:macLength])

	return iso7816.Response{Data: data, Status: status}
}

func decodeHex(t testing.TB, text string) []byte {
	t.Helper()

	data, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func recordKeys(size int) Keys {
	keys := Keys{ENC: make([]byte, size), MAC: make([]byte, size)}
	for i := range size {
		keys.ENC[i] = byte(i)
		keys.MAC[i] = byte(0x20 + i)
	}

	return keys
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
