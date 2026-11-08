package iso7816

import (
	"errors"
	"fmt"
	"io"
	"testing"

	baseiso7816 "github.com/telesma-app/iso7816"
	openpgptransport "github.com/telesma-app/openpgp/transport"
)

func TestSelectActivatesApplication(t *testing.T) {
	for _, test := range []struct {
		name     string
		response []byte
	}{
		{name: "empty", response: selectResponse},
		{name: "FCI", response: []byte{0x6f, 0x00, 0x90, 0x00}},
	} {
		t.Run(test.name, func(t *testing.T) {
			card := &fakeCard{t: t, exchanges: []exchange{{
				request: selectAPDU, response: test.response,
			}}}

			if err := Select(t.Context(), card); err != nil {
				t.Fatal(err)
			}

			if card.closeCalls != 0 {
				t.Error("Select closed borrowed card")
			}
		})
	}
}

func TestSelectReturnsApplicationRejection(t *testing.T) {
	for _, test := range []struct {
		name   string
		status baseiso7816.StatusWord
	}{
		{name: "missing application", status: 0x6a82},
		{name: "initialisation state", status: 0x6285},
	} {
		t.Run(test.name, func(t *testing.T) {
			card := &fakeCard{t: t, exchanges: []exchange{{
				request: selectAPDU, response: []byte{test.status.SW1(), test.status.SW2()},
			}}}

			err := Select(t.Context(), card)

			var apdu *baseiso7816.APDUError
			if !errors.As(err, &apdu) || apdu.StatusWord() != test.status {
				t.Fatalf("Select = %v, want APDU error %s", err, test.status)
			}

			if card.closeCalls != 0 {
				t.Error("Select closed borrowed card")
			}
		})
	}
}

func TestOpenInitialisationStateTransfersUsableCard(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{
		{request: selectAPDU, response: []byte{0x62, 0x85}},
		{request: []byte{0x00, 0x44, 0x00, 0x00}, response: []byte{0x90, 0x00}},
	}}

	device, err := Open(t.Context(), card)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := device.Close(); err != nil {
			t.Error(err)
		}
	})

	if card.closeCalls != 0 {
		t.Error("Open closed initialisation-state card")
	}

	if len(card.exchanges) != 1 {
		t.Fatalf("remaining exchanges = %d, want explicit activation pending", len(card.exchanges))
	}

	response, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0x44})
	if err != nil {
		t.Fatal(err)
	}

	if response.Status != 0x9000 || len(response.Data) != 0 {
		t.Errorf("activation response = %+v, want empty success", response)
	}

	if len(card.exchanges) != 0 {
		t.Errorf("remaining exchanges = %d, want 0", len(card.exchanges))
	}

	if err := device.Close(); err != nil {
		t.Fatal(err)
	}

	if card.closeCalls != 1 {
		t.Errorf("Close calls = %d, want 1", card.closeCalls)
	}
}

func TestOpenRejectsOtherSelectStatuses(t *testing.T) {
	for _, test := range []struct {
		name   string
		status baseiso7816.StatusWord
	}{
		{name: "other warning", status: 0x6283},
		{name: "conditions not satisfied", status: 0x6985},
		{name: "missing application", status: 0x6a82},
	} {
		t.Run(test.name, func(t *testing.T) {
			card := &fakeCard{t: t, exchanges: []exchange{{
				request: selectAPDU, response: []byte{test.status.SW1(), test.status.SW2()},
			}}}

			device, err := Open(t.Context(), card)
			if device != nil {
				t.Cleanup(func() {
					if err := device.Close(); err != nil {
						t.Error(err)
					}
				})
				t.Fatal("Open returned a transport for rejected selection")
			}

			var apdu *baseiso7816.APDUError
			if !errors.As(err, &apdu) || apdu.StatusWord() != test.status {
				t.Fatalf("Open = %v, want APDU error %s", err, test.status)
			}

			if card.closeCalls != 0 {
				t.Error("failed Open closed caller's card")
			}
		})
	}
}

func TestOpenDoesNotAcceptInitialisationStatusInIOError(t *testing.T) {
	for _, test := range []struct {
		name        string
		invalidated bool
	}{
		{name: "APDU cause"},
		{name: "invalidated connection", invalidated: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			apduCause := &baseiso7816.APDUError{SW1: 0x62, SW2: 0x85}

			var cause error = apduCause
			if test.invalidated {
				cause = &openpgptransport.DeviceInvalidatedError{Err: cause}
			}

			cardError := fmt.Errorf("card exchange failed: %w", cause)
			card := &fakeCard{t: t, exchanges: []exchange{{request: selectAPDU, err: cardError}}}

			device, err := Open(t.Context(), card)
			if device != nil {
				t.Cleanup(func() {
					if err := device.Close(); err != nil {
						t.Error(err)
					}
				})
				t.Fatal("Open accepted an I/O failure as a selected application")
			}

			if !errors.Is(err, cardError) || !errors.Is(err, apduCause) {
				t.Fatalf("Open error = %v, want card and APDU causes preserved", err)
			}

			var ioError *openpgptransport.IOError
			if !errors.As(err, &ioError) || ioError.Operation != openpgptransport.IOTransmit {
				t.Errorf("Open error = %v, want transmit I/O error", err)
			}

			var invalidated *openpgptransport.DeviceInvalidatedError
			if test.invalidated && !errors.As(err, &invalidated) {
				t.Errorf("Open error = %v, want device invalidation preserved", err)
			}

			if card.closeCalls != 0 {
				t.Error("failed Open closed caller's card")
			}
		})
	}
}

func TestOpenFailurePreservesCallerOwnership(t *testing.T) {
	for _, test := range []struct {
		name     string
		response []byte
		err      error
	}{
		{name: "missing application", response: []byte{0x6a, 0x82}},
		{name: "malformed response", response: []byte{0x90}},
		{name: "I/O failure", err: io.ErrClosedPipe},
	} {
		t.Run(test.name, func(t *testing.T) {
			card := &fakeCard{t: t, exchanges: []exchange{{request: selectAPDU, response: test.response, err: test.err}}}

			device, err := Open(t.Context(), card)
			if device != nil || err == nil {
				t.Fatalf("Open = %v, %v; want failure", device, err)
			}

			if card.closeCalls != 0 {
				t.Error("failed Open closed caller's card")
			}
		})
	}
}
