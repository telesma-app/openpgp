package iso7816

import (
	"bytes"
	"context"
	"errors"
	"testing"

	baseiso7816 "github.com/telesma-app/iso7816"
	openpgptransport "github.com/telesma-app/openpgp/transport"
)

func TestPreCanceledRawExchangeDoesNotTransmit(t *testing.T) {
	card := newFakeCard(t, nil)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	response, err := Exchange(ctx, card, baseiso7816.Command{INS: 0x20, P2: 0x81})

	var invalidated *openpgptransport.DeviceInvalidatedError
	if !errors.Is(err, context.Canceled) || errors.As(err, &invalidated) {
		t.Errorf("Exchange = %v, want cancellation without invalidation", err)
	}

	if response.Data != nil || response.Status != 0 || card.closeCalls != 0 {
		t.Errorf("Exchange = %+v, closes=%d; want empty response without closing the borrowed card", response, card.closeCalls)
	}
}

func TestExchangeReturnsUninterpretedStatus(t *testing.T) {
	card := newFakeCard(t, []exchange{{
		request: []byte{0x00, 0x20, 0x00, 0x81}, response: []byte{0x63, 0xc3},
	}})

	response, err := Exchange(t.Context(), card, baseiso7816.Command{INS: 0x20, P2: 0x81})
	if err != nil {
		t.Fatal(err)
	}

	if response.Status != 0x63c3 {
		t.Errorf("status = %s, want 63c3", response.Status)
	}
}

func TestExchangeCollectsGetResponse(t *testing.T) {
	card := newFakeCard(t, []exchange{
		{request: []byte{0x00, 0xca, 0x00, 0x6e, 0x05, 0x5c, 0x03, 0x5f, 0xc1, 0x05, 0x00}, response: []byte{0x53, 0x03, 0x61, 0x03}},
		{request: []byte{0x00, 0xc0, 0x00, 0x00, 0x03}, response: []byte{0x70, 0x01, 0x01, 0x90, 0x00}},
	})

	response, err := Exchange(t.Context(), card, baseiso7816.Command{
		INS: 0xca, P2: 0x6e, Data: []byte{0x5c, 0x03, 0x5f, 0xc1, 0x05}, Le: 256,
	})
	if err != nil {
		t.Fatal(err)
	}

	if response.Status != 0x9000 || !bytes.Equal(response.Data, []byte{0x53, 0x03, 0x70, 0x01, 0x01}) {
		t.Errorf("response = %x, %s", response.Data, response.Status)
	}

	if len(card.exchanges) != 0 {
		t.Errorf("remaining exchanges = %d", len(card.exchanges))
	}
}

func TestExchangeCollectsResponseUsingPlainCLA(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cla      byte
		encoding baseiso7816.Encoding
	}{
		{name: "short", cla: 0x04, encoding: baseiso7816.EncodingShort},
		{name: "extended", cla: 0x04, encoding: baseiso7816.EncodingExtended},
		{name: "vendor short", cla: 0x84, encoding: baseiso7816.EncodingShort},
		{name: "vendor extended", cla: 0x84, encoding: baseiso7816.EncodingExtended},
		{name: "proprietary short", cla: 0x80, encoding: baseiso7816.EncodingShort},
		{name: "proprietary extended", cla: 0x80, encoding: baseiso7816.EncodingExtended},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := bytes.Repeat([]byte{0xa5}, 24)
			request := append([]byte{tc.cla, 0xca, 0x00, 0x6e, 24}, data...)
			request = append(request, 0)

			if tc.encoding == baseiso7816.EncodingExtended {
				request = append([]byte{tc.cla, 0xca, 0x00, 0x6e, 0, 0, 24}, data...)
				request = append(request, 0x01, 0x00)
			}

			card := newFakeCard(t, []exchange{
				{request: request, response: []byte{1, 2, 0x61, 0}},
				{request: []byte{0x00, 0xc0, 0, 0, 0}, response: []byte{3, 4, 0x61, 2}},
				{request: []byte{0x00, 0xc0, 0, 0, 2}, response: []byte{5, 6, 0x90, 0}},
			})

			response, err := Exchange(t.Context(), card, baseiso7816.Command{
				CLA: tc.cla, INS: 0xca, P2: 0x6e, Data: data, Le: 256, Encoding: tc.encoding,
			})
			if err != nil {
				t.Fatal(err)
			}

			if response.Status != 0x9000 || !bytes.Equal(response.Data, []byte{1, 2, 3, 4, 5, 6}) {
				t.Errorf("collected response = %x, %s", response.Data, response.Status)
			}

			if len(card.exchanges) != 0 {
				t.Errorf("remaining exchanges = %d", len(card.exchanges))
			}
		})
	}
}

func TestSecureShortExchangeChainsProtectedBodyBeforePlainGetResponse(t *testing.T) {
	for _, tc := range []struct {
		name string
		cla  byte
	}{
		{name: "standard", cla: 0x04},
		{name: "vendor", cla: 0x84},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := bytes.Repeat([]byte{0xab}, 600)
			card := newFakeCard(t, []exchange{
				{request: append([]byte{tc.cla | 0x10, 0xdb, 0x3f, 0xff, 0xfa}, data[:250]...), response: []byte{0x90, 0x00}},
				{request: append([]byte{tc.cla | 0x10, 0xdb, 0x3f, 0xff, 0xfa}, data[250:500]...), response: []byte{0x90, 0x00}},
				{request: append(append([]byte{tc.cla, 0xdb, 0x3f, 0xff, 0x64}, data[500:]...), 0), response: []byte{1, 2, 0x61, 3}},
				{request: []byte{0x00, 0xc0, 0, 0, 3}, response: []byte{3, 4, 5, 0x90, 0}},
			})

			response, err := Exchange(t.Context(), card, baseiso7816.Command{
				CLA: tc.cla, INS: 0xdb, P1: 0x3f, P2: 0xff, Data: data, Le: 256, Encoding: baseiso7816.EncodingShort,
			})
			if err != nil {
				t.Fatal(err)
			}

			if response.Status != 0x9000 || !bytes.Equal(response.Data, []byte{1, 2, 3, 4, 5}) {
				t.Errorf("collected response = %x, %s", response.Data, response.Status)
			}

			if len(card.exchanges) != 0 {
				t.Errorf("remaining exchanges = %d", len(card.exchanges))
			}
		})
	}
}

func TestExchangePreservesExplicitSecureGetResponse(t *testing.T) {
	card := newFakeCard(t, []exchange{
		{request: []byte{0x04, 0xc0, 0x00, 0x00, 0x01, 0xaa, 0x00}, response: []byte{1, 0x61, 1}},
		{request: []byte{0x00, 0xc0, 0x00, 0x00, 0x01}, response: []byte{2, 0x90, 0x00}},
	})

	response, err := Exchange(t.Context(), card, baseiso7816.Command{
		CLA: 0x04, INS: 0xc0, Data: []byte{0xaa}, Le: 256,
	})
	if err != nil {
		t.Fatal(err)
	}

	if response.Status != 0x9000 || !bytes.Equal(response.Data, []byte{1, 2}) {
		t.Errorf("collected response = %x, %s", response.Data, response.Status)
	}

	if len(card.exchanges) != 0 {
		t.Errorf("remaining exchanges = %d", len(card.exchanges))
	}
}

func TestExchangeChainsShortAPDUs(t *testing.T) {
	data := bytes.Repeat([]byte{0xab}, 600)
	card := newFakeCard(t, []exchange{
		{request: append([]byte{0x10, 0x2a, 0x9e, 0x9a, 0xfa}, data[:250]...), response: []byte{0x90, 0x00}},
		{request: append([]byte{0x10, 0x2a, 0x9e, 0x9a, 0xfa}, data[250:500]...), response: []byte{0x90, 0x00}},
		{request: append(append([]byte{0x00, 0x2a, 0x9e, 0x9a, 0x64}, data[500:]...), 0x00), response: []byte{0x7c, 0x00, 0x90, 0x00}},
	})

	response, err := Exchange(t.Context(), card, baseiso7816.Command{
		INS: 0x2a, P1: 0x9e, P2: 0x9a, Data: data, Le: 256,
	})
	if err != nil {
		t.Fatal(err)
	}

	if response.Status != 0x9000 || !bytes.Equal(response.Data, []byte{0x7c, 0x00}) {
		t.Errorf("response = %x, %s", response.Data, response.Status)
	}

	if len(card.exchanges) != 0 {
		t.Errorf("remaining exchanges = %d", len(card.exchanges))
	}
}

func TestExchangeHonorsExplicitExtendedEncodingWithoutChaining(t *testing.T) {
	data := bytes.Repeat([]byte{0xab}, 600)
	request := append([]byte{0x00, 0x2a, 0x9e, 0x9a, 0x00, 0x02, 0x58}, data...)
	request = append(request, 0x01, 0x00)
	card := newFakeCard(t, []exchange{
		{request: request, response: []byte{0x7c, 0x00, 0x90, 0x00}},
	})

	response, err := Exchange(t.Context(), card, baseiso7816.Command{
		INS: 0x2a, P1: 0x9e, P2: 0x9a, Data: data, Le: 256, Encoding: baseiso7816.EncodingExtended,
	}, WithMaxCommandAPDULength(609))
	if err != nil {
		t.Fatal(err)
	}

	if response.Status != 0x9000 || !bytes.Equal(response.Data, []byte{0x7c, 0x00}) {
		t.Errorf("response = %x, %s", response.Data, response.Status)
	}

	if len(card.exchanges) != 0 {
		t.Errorf("remaining exchanges = %d, want one complete extended APDU", len(card.exchanges))
	}
}

func TestExchangeCollectsResponseAfterChainedCommand(t *testing.T) {
	data := bytes.Repeat([]byte{0xab}, 256)
	card := newFakeCard(t, []exchange{
		{request: append([]byte{0x10, 0x2a, 0x9e, 0x9a, 0xfa}, data[:250]...), response: []byte{0x90, 0x00}},
		{request: []byte{0x00, 0x2a, 0x9e, 0x9a, 0x06, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x00}, response: []byte{0x7c, 0x02, 0x61, 0x02}},
		{request: []byte{0x00, 0xc0, 0x00, 0x00, 0x02}, response: []byte{0x82, 0x00, 0x90, 0x00}},
	})

	response, err := Exchange(t.Context(), card, baseiso7816.Command{
		INS: 0x2a, P1: 0x9e, P2: 0x9a, Data: data, Le: 256,
	})
	if err != nil {
		t.Fatal(err)
	}

	if response.Status != 0x9000 || !bytes.Equal(response.Data, []byte{0x7c, 0x02, 0x82, 0x00}) {
		t.Errorf("response = %x, %s", response.Data, response.Status)
	}

	if len(card.exchanges) != 0 {
		t.Errorf("remaining exchanges = %d", len(card.exchanges))
	}
}
