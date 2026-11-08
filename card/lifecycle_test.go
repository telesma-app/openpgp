package card_test

import (
	"bytes"
	"errors"
	"testing"

	baseiso7816 "github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/card"
	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport/iso7816"
)

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

func TestActivateApplicationSelectedInInitializationState(t *testing.T) {
	aid := []byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 6, 0, 0, 0, 1, 0, 0}

	device, raw := newLifecycleDevice(t,
		encodingExchange{
			request:  []byte{0, 0xa4, 4, 0, 6, 0xd2, 0x76, 0, 1, 0x24, 1, 0},
			response: []byte{0x62, 0x85},
		},
		encodingExchange{request: []byte{0, 0x44, 0, 0}, response: []byte{0x90, 0}},
		encodingExchange{request: []byte{0, 0xca, 0, 0x4f, 0}, response: append(aid, 0x90, 0)},
	)
	if raw.closeCalls != 0 {
		t.Fatalf("Close calls after Open = %d, want 0", raw.closeCalls)
	}

	if err := device.ActivateFile(t.Context()); err != nil {
		t.Fatal(err)
	}

	got, err := device.GetData(t.Context(), protocol.ApplicationIdentifierObject)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, aid) {
		t.Errorf("AID after activation = %x, want %x", got, aid)
	}
}

func TestTerminateAndActivateApplication(t *testing.T) {
	aid := []byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 6, 0, 0, 0, 1, 0, 0}

	device, raw := newLifecycleDevice(t,
		encodingExchange{
			request:  []byte{0, 0xa4, 4, 0, 6, 0xd2, 0x76, 0, 1, 0x24, 1, 0},
			response: []byte{0x90, 0},
		},
		encodingExchange{
			request:  []byte{0, 0x20, 0, 0x83, 8, '1', '2', '3', '4', '5', '6', '7', '8'},
			response: []byte{0x90, 0},
		},
		encodingExchange{request: []byte{0, 0xe6, 0, 0}, response: []byte{0x90, 0}},
		encodingExchange{
			request:  []byte{0, 0xa4, 4, 0, 6, 0xd2, 0x76, 0, 1, 0x24, 1, 0},
			response: []byte{0x62, 0x85},
		},
		encodingExchange{request: []byte{0, 0x44, 0, 0}, response: []byte{0x90, 0}},
		encodingExchange{request: []byte{0, 0xca, 0, 0x4f, 0}, response: append(aid, 0x90, 0)},
	)
	if err := device.Verify(t.Context(), protocol.PW3, []byte("12345678")); err != nil {
		t.Fatal(err)
	}

	if err := device.TerminateDF(t.Context(), nil); err != nil {
		t.Fatal(err)
	}

	err := device.Select(t.Context())

	var apduError *baseiso7816.APDUError
	if !errors.As(err, &apduError) || apduError.StatusWord() != 0x6285 {
		t.Fatalf("Select after termination = %v, want APDU error 6285", err)
	}

	if raw.closeCalls != 0 {
		t.Fatalf("Close calls after termination = %d, want 0", raw.closeCalls)
	}

	if err := device.ActivateFile(t.Context()); err != nil {
		t.Fatal(err)
	}

	got, err := device.GetData(t.Context(), protocol.ApplicationIdentifierObject)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, aid) {
		t.Errorf("AID after activation = %x, want %x", got, aid)
	}
}
