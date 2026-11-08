package iso7816

import (
	"bytes"
	"errors"
	"io"
	"testing"

	baseiso7816 "github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/card"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
	openpgptransport "github.com/telesma-app/openpgp/transport"
)

func TestNewTakesOwnershipWithoutIO(t *testing.T) {
	raw := &fakeCard{t: t}

	connection := New(raw)
	if raw.closeCalls != 0 {
		t.Fatal("New closed the card")
	}

	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}

	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := connection.Exchange(t.Context(), baseiso7816.Command{INS: 0xcb}); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("exchange after Close = %v, want closed pipe without I/O", err)
	}

	if raw.closeCalls != 1 {
		t.Errorf("card Close calls = %d, want 1", raw.closeCalls)
	}
}

func TestPreselectMFReadThenSelectAndDeviceHandoff(t *testing.T) {
	raw := &fakeCard{t: t, exchanges: []exchange{
		{request: []byte{0, 0xcb, 0x2f, 0, 2, 0x5c, 0, 0}, response: []byte{0x61, 0, 0x90, 0}},
		{request: selectAPDU, response: selectResponse},
		{request: []byte{0, 0xca, 0x5f, 0x50, 0}, response: []byte{'u', 'r', 'l', 0x90, 0}},
	}}
	connection := New(raw)
	closeResource := connection.Close

	t.Cleanup(func() {
		if err := closeResource(); err != nil {
			t.Error(err)
		}

		if raw.closeCalls != 1 || len(raw.exchanges) != 0 {
			t.Errorf("Close calls = %d, remaining APDUs = %d; want 1, 0", raw.closeCalls, len(raw.exchanges))
		}
	})

	commands := client.NewClient(connection)

	contents, err := commands.GetDataOdd(t.Context(), protocol.DirectoryFile)
	if err != nil || !bytes.Equal(contents, []byte{0x61, 0}) {
		t.Fatalf("pre-selection EF.DIR = %x, %v; want 6100", contents, err)
	}

	if raw.closeCalls != 0 {
		t.Fatal("MF read closed the connection")
	}

	if err := commands.Select(t.Context()); err != nil {
		t.Fatal(err)
	}

	device := card.New(connection)
	closeResource = device.Close

	contents, err = device.GetData(t.Context(), protocol.URLObject)
	if err != nil || !bytes.Equal(contents, []byte("url")) {
		t.Fatalf("selected Device read = %x, %v; want url", contents, err)
	}

	if err := device.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := device.GetData(t.Context(), protocol.URLObject); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("Device after Close = %v, want closed pipe", err)
	}
}

func TestPreselectMFRejectionPreservesConnectionForSelect(t *testing.T) {
	raw := &fakeCard{t: t, exchanges: []exchange{
		{request: []byte{0, 0xcb, 0x2f, 1, 2, 0x5c, 0, 0}, response: []byte{0x6a, 0x82}},
		{request: selectAPDU, response: selectResponse},
	}}
	connection := New(raw)

	t.Cleanup(func() {
		if err := connection.Close(); err != nil {
			t.Error(err)
		}

		if raw.closeCalls != 1 || len(raw.exchanges) != 0 {
			t.Errorf("Close calls = %d, remaining APDUs = %d; want 1, 0", raw.closeCalls, len(raw.exchanges))
		}
	})

	commands := client.NewClient(connection)

	_, err := commands.GetDataOdd(t.Context(), protocol.ATRInfoFile)

	var (
		apdu        *baseiso7816.APDUError
		invalidated *openpgptransport.DeviceInvalidatedError
	)
	if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6a82 || errors.As(err, &invalidated) {
		t.Fatalf("MF rejection = %v, want ordinary APDU error 6a82", err)
	}

	if raw.closeCalls != 0 {
		t.Fatal("MF rejection closed the card")
	}

	if err := commands.Select(t.Context()); err != nil {
		t.Fatalf("SELECT after unavailable MF file: %v", err)
	}
}

func TestPreselectFailureInvalidatesOwnedCard(t *testing.T) {
	for _, test := range []struct {
		name     string
		response []byte
		err      error
		cause    error
	}{
		{name: "transport failure", err: io.ErrUnexpectedEOF, cause: io.ErrUnexpectedEOF},
		{name: "malformed response", response: []byte{0x90}, cause: baseiso7816.ErrInvalidResponse},
	} {
		t.Run(test.name, func(t *testing.T) {
			closeErr := errors.New("card close failed")
			raw := &fakeCard{t: t, closeErr: closeErr, exchanges: []exchange{{
				request: []byte{0, 0xcb, 0x2f, 0, 2, 0x5c, 0, 0}, response: test.response, err: test.err,
			}}}
			connection := New(raw)

			t.Cleanup(func() {
				if err := connection.Close(); !errors.Is(err, closeErr) {
					t.Errorf("Close = %v, want close cause", err)
				}
			})

			commands := client.NewClient(connection)

			_, err := commands.GetDataOdd(t.Context(), protocol.DirectoryFile)

			var invalidated *openpgptransport.DeviceInvalidatedError
			if !errors.As(err, &invalidated) || !errors.Is(err, test.cause) || !errors.Is(err, closeErr) {
				t.Fatalf("MF read failure = %v, want invalidation with original and close causes", err)
			}

			if raw.closeCalls != 1 || len(raw.exchanges) != 0 {
				t.Errorf("Close calls = %d, remaining APDUs = %d; want 1, 0", raw.closeCalls, len(raw.exchanges))
			}

			if err := commands.Select(t.Context()); !errors.Is(err, io.ErrClosedPipe) {
				t.Errorf("SELECT after invalidation = %v, want closed pipe", err)
			}

			if raw.closeCalls != 1 {
				t.Errorf("Close calls after attempted reuse = %d, want 1", raw.closeCalls)
			}
		})
	}
}
