package iso7816

import (
	"bytes"
	"context"
	"testing"
)

var (
	selectAPDU     = []byte{0x00, 0xa4, 0x04, 0x00, 0x06, 0xd2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x00}
	selectResponse = []byte{0x90, 0x00}
)

type exchange struct {
	request  []byte
	response []byte
	err      error
	after    func()
}

type fakeCard struct {
	t          testing.TB
	exchanges  []exchange
	closeCalls int
	closeErr   error
}

func (c *fakeCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	c.t.Helper()

	if len(c.exchanges) == 0 {
		c.t.Fatalf("unexpected APDU: %x", apdu)
	}

	next := c.exchanges[0]

	c.exchanges = c.exchanges[1:]
	if !bytes.Equal(apdu, next.request) {
		c.t.Fatalf("APDU = %x, want %x", apdu, next.request)
	}

	if next.after != nil {
		next.after()
	}

	return next.response, next.err
}

func (c *fakeCard) Close() error {
	c.closeCalls++
	return c.closeErr
}

func newTransport(t testing.TB, exchanges ...exchange) (*Transport, *fakeCard) {
	t.Helper()
	card := &fakeCard{
		t: t,
		exchanges: append([]exchange{{
			request: selectAPDU, response: selectResponse,
		}}, exchanges...),
	}

	device, err := Open(context.Background(), card)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := device.Close(); err != nil && card.closeErr == nil {
			t.Error(err)
		}
	})

	return device, card
}
