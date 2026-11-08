package card_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/telesma-app/openpgp/card"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/transport/iso7816"
)

type encodingExchange struct {
	request  []byte
	response []byte
}

type encodingCard struct {
	t          testing.TB
	exchanges  []encodingExchange
	closeCalls int
}

func (c *encodingCard) Transmit(_ context.Context, apdu []byte) ([]byte, error) {
	c.t.Helper()

	if len(c.exchanges) == 0 {
		c.t.Fatalf("unexpected APDU: %x", apdu)
	}

	next := c.exchanges[0]

	c.exchanges = c.exchanges[1:]
	if !bytes.Equal(apdu, next.request) {
		c.t.Fatalf("APDU = %x, want %x", apdu, next.request)
	}

	return next.response, nil
}

func (c *encodingCard) Close() error {
	c.closeCalls++
	return nil
}

func newEncodingDevice(t testing.TB, options []client.Option, exchanges ...encodingExchange) *card.Device {
	t.Helper()
	raw := &encodingCard{
		t: t,
		exchanges: append([]encodingExchange{{
			request:  []byte{0x00, 0xa4, 0x04, 0x00, 0x06, 0xd2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x00},
			response: []byte{0x90, 0x00},
		}}, exchanges...),
	}
	closeResource := raw.Close

	t.Cleanup(func() {
		if err := closeResource(); err != nil {
			t.Error(err)
		}

		if raw.closeCalls != 1 {
			t.Errorf("Close calls = %d, want 1", raw.closeCalls)
		}

		if len(raw.exchanges) != 0 {
			t.Errorf("remaining exchanges = %d, want 0", len(raw.exchanges))
		}
	})

	// This peer accepts full extended APDUs; these tests exercise the client's
	// encoding choice independently of transport fragmentation limits.
	connection, err := iso7816.Open(t.Context(), raw, iso7816.WithMaxCommandAPDULength(65544))
	if err != nil {
		t.Fatal(err)
	}

	device := card.New(connection, options...)
	closeResource = device.Close

	return device
}

func newLifecycleDevice(t testing.TB, exchanges ...encodingExchange) (*card.Device, *encodingCard) {
	t.Helper()
	raw := &encodingCard{t: t, exchanges: exchanges}
	closeResource := raw.Close

	t.Cleanup(func() {
		if err := closeResource(); err != nil {
			t.Error(err)
		}

		if raw.closeCalls != 1 {
			t.Errorf("Close calls = %d, want 1", raw.closeCalls)
		}

		if len(raw.exchanges) != 0 {
			t.Errorf("remaining exchanges = %d, want 0", len(raw.exchanges))
		}
	})

	connection, err := iso7816.Open(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}

	device := card.New(connection)
	closeResource = device.Close

	return device, raw
}
