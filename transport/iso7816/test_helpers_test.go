package iso7816

import (
	"bytes"
	"context"
	"testing"
	"time"
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

func newFakeCard(t testing.TB, exchanges []exchange) *fakeCard {
	t.Helper()
	card := &fakeCard{t: t, exchanges: exchanges}

	t.Cleanup(func() {
		if len(card.exchanges) != 0 {
			t.Errorf("remaining exchanges = %d, want 0; next APDU = %x", len(card.exchanges), card.exchanges[0].request)
		}
	})

	return card
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
	card := newFakeCard(t, append([]exchange{{
		request: selectAPDU, response: selectResponse,
	}}, exchanges...))

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

func receive[T any](t testing.TB, ch <-chan T, failure string) T {
	t.Helper()

	select {
	case value := <-ch:
		return value
	case <-time.After(time.Second):
		t.Fatal(failure)

		var zero T

		return zero
	}
}
