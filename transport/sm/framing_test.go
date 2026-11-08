package sm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/telesma-app/iso7816"
	openpgpiso7816 "github.com/telesma-app/openpgp/transport/iso7816"
)

// OpenSSL 3.5.9 independently generated this complete response using
// AES-128-CBC (-nopad) and CMAC with the construction in Sec. 7.5, pp. 84-86.
// ENC is 00..0f, MAC is 20..2f, RND is 10..1f, and plaintext[i] is byte(i*7+3).
// CBC uses RND directly; CMAC receives AES_K^-1(RND) || pad(DO87 || DO99).
const framingResponseHex = "878202c101add2ed9dcb6c77261fef6d655c174631cf6ebf51f5bd35d45f162d2aea1330643d1df9162973cc0ae68f4f" +
	"183977fbf585978bd3c32f585e5f8764780910d4c2c6693a01f693cb97b889b5d75cda2cb1f4365762091ef89e02b17a" +
	"4a6ea774c4dda96b2c9e751dfa5515ceb7a286bdd7f2d7cdf6956f028ea67ea828a1670ca428512500389d162fa0ec8a" +
	"5fb480eefaa4b95fcd3921e0cda16087445c47b130d312afbe327ae4a5cb97be3745c1a2d18029561c1ee2d5853798de" +
	"ac16ec73148151e4f807fc0a88013339aaf670e52857a4fc58e8c729892f60dc922a6868998b8c5636e3c106933a35a0" +
	"b21ffe4a1d0241eac763bdcb704691efa3971f967acbd532d14ca8d2a41fc3fc8216ac0a1f80f885873a08bfb1c886c5" +
	"774464035a6718940f752939c6a17adc90e6b8c8b886cadc9b346211b28c0efbe6571ac448c9f3ed139805a3dd6755f0" +
	"8abfd699ba7a434ad724e2015174d0511e095fb84c3c085d24a5a22a616b95d5d6cd06dab4a8b57fc1c43d2152a11f3f" +
	"146b58b3d60e0ac4a477a21fa91dfcff051c59e150c3f3f1c1944e375b92717ecba0cc1913f74e915a9b769bbb1e909f" +
	"d8482077ce1fb6eed344683c7bed27cab04d06ff8bca696e7d1fcd58ace72f7f813b1109014faf123ae264ab8344d079" +
	"7714a1a4a53d9477aad3e38d8aab3a32ec511fcd0f87fa5827c2ecbba7ad7519a5c69dabed56735f8192530cc3defb0b" +
	"334c7f495aa39edd4f4eeb553f10ccc3f95e8d574d8d200d5e8360dfb7cdc7864b11256c6699d833a09ec8360332d7f5" +
	"a1000f4d28a7ef80c72012ba6788ba8f6cfbebecdafbc62d8d401455a842163ec73cc0bbaaec7b887f9bb3631a740462" +
	"f6df5bbf008849268ddca977d00ef409931ef7770ab8c4201f401db9896eac44883addb19cefa7e1141befedd49fcbd5" +
	"f5018a1dc179ce3cd7d792e9475d8878cfaf2f14c3d9daeb93a7f1da2788734abd1209aea1990290008e08094c4bc3ce" +
	"e2fc9b"

type framingCard struct {
	t          testing.TB
	response   []byte
	putBody    []byte
	calls      int
	closeCalls int
}

func (c *framingCard) expectAPDU(got []byte, want string) {
	c.t.Helper()

	if !bytes.Equal(got, recordHex(c.t, want)) {
		c.t.Fatalf("APDU %d = %x, want %s", c.calls, got, want)
	}
}

func (c *framingCard) Transmit(_ context.Context, apdu []byte) ([]byte, error) {
	c.t.Helper()

	call := c.calls
	c.calls++

	switch call {
	case 0:
		c.expectAPDU(apdu, "00a4040006d2760001240100")

		return []byte{0x90, 0}, nil
	case 1:
		c.expectAPDU(apdu, "0084000010")

		return recordHex(c.t, "000102030405060708090a0b0c0d0e0f9000"), nil
	case 2, 3:
		if len(apdu) != 255 || !bytes.Equal(apdu[:5], recordHex(c.t, "1cda7f21fa")) {
			c.t.Fatalf("intermediate PUT DATA fragment %d = %x", call, apdu)
		}

		c.putBody = append(c.putBody, apdu[5:]...)

		return []byte{0x90, 0}, nil
	case 4:
		if len(apdu) != 129 || !bytes.Equal(apdu[:5], recordHex(c.t, "0cda7f217b")) || apdu[len(apdu)-1] != 0 {
			c.t.Fatalf("final PUT DATA fragment = %x", apdu)
		}

		c.putBody = append(c.putBody, apdu[5:len(apdu)-1]...)
		// Independent OpenSSL AES-128-CBC/CMAC vector for 600 plaintext
		// bytes, plaintext[i]=byte(i), using RND 00..0f and the keys above.
		digest := sha256.Sum256(c.putBody)
		if !bytes.Equal(digest[:], recordHex(c.t, "2eab96807a13a77e4e678fe13fbd56e20d6942b7c77f63f8b4e95e28eac6116e")) {
			c.t.Fatalf("assembled PUT DATA SHA-256 = %x", digest)
		}

		return []byte{0x90, 0}, nil
	case 5:
		c.expectAPDU(apdu, "0084000010")

		return recordHex(c.t, "101112131415161718191a1b1c1d1e1f9000"), nil
	case 6:
		// Independent OpenSSL record for GET DATA 7F21 with logical Le 256
		// and RND 10..1f. There is one challenge per logical command.
		c.expectAPDU(apdu, "0cca7f210d9701008e084e96d93e92b2f3ba00")

		return append(bytes.Clone(c.response[:256]), 0x61, 0), nil
	case 7:
		c.expectAPDU(apdu, "00c0000000")

		return append(bytes.Clone(c.response[256:512]), 0x61, 0xd3), nil
	case 8:
		c.expectAPDU(apdu, "00c00000d3")

		return append(bytes.Clone(c.response[512:]), 0x90, 0), nil
	default:
		c.t.Fatalf("unexpected APDU %d = %x", call, apdu)
		return nil, nil
	}
}

func (c *framingCard) Close() error {
	c.closeCalls++
	return nil
}

func TestTransportProtectsBeforeChainingAndAuthenticatesAfterCollection(t *testing.T) {
	raw := &framingCard{t: t, response: recordHex(t, framingResponseHex)}
	if len(raw.response) != 723 {
		t.Fatalf("protected response has %d bytes, want 723", len(raw.response))
	}

	connection, err := openpgpiso7816.Open(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := connection.Close(); err != nil {
			t.Error(err)
		}
	})

	channel, err := New(connection, Parameters{Keys: recordKeys(16), Encoding: iso7816.EncodingShort})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := channel.Close(); err != nil {
			t.Error(err)
		}
	})

	data := make([]byte, 600)
	for i := range data {
		data[i] = byte(i)
	}

	response, err := channel.Exchange(t.Context(), iso7816.Command{
		INS: 0xda, P1: 0x7f, P2: 0x21, Data: data, Encoding: iso7816.EncodingShort,
	})
	if err != nil || response.Status != 0x9000 || len(response.Data) != 0 {
		t.Fatalf("chained PUT DATA = %+v, %v", response, err)
	}

	response, err = channel.Exchange(t.Context(), iso7816.Command{
		INS: 0xca, P1: 0x7f, P2: 0x21, Le: 256, Encoding: iso7816.EncodingShort,
	})
	if err != nil {
		t.Fatal(err)
	}

	plaintext := make([]byte, 700)
	for i := range plaintext {
		plaintext[i] = byte(i*7 + 3)
	}

	if response.Status != 0x9000 || !bytes.Equal(response.Data, plaintext) {
		t.Errorf("collected GET DATA = status %s data %x, want status 9000 data %x", response.Status, response.Data, plaintext)
	}

	if raw.calls != 9 || len(raw.putBody) != 623 {
		t.Errorf("framing calls = %d, PUT DATA body size = %d; want 9 calls and 623 bytes", raw.calls, len(raw.putBody))
	}

	for range 2 {
		if err := channel.Close(); err != nil {
			t.Fatal(err)
		}
	}

	if raw.closeCalls != 1 {
		t.Errorf("raw Close calls = %d, want 1", raw.closeCalls)
	}
}
