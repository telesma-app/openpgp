package pcsc_test

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	baseiso7816 "github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/card"
	"github.com/telesma-app/openpgp/client"
	openpgpiso7816 "github.com/telesma-app/openpgp/transport/iso7816"
	nativepcsc "github.com/telesma-app/pcsc"
)

// TestHardwareChallenge reads challenges without PINs, writes or resets.
// Diagnostics include APDUs, lengths and status words, never random bytes.
func TestHardwareChallenge(t *testing.T) {
	if os.Getenv("OPENPGP_TEST") != "1" {
		t.Skip("set OPENPGP_TEST=1 to request challenges from a selected card")
	}

	reader := os.Getenv("OPENPGP_TEST_READER")
	if reader == "" {
		t.Fatal("OPENPGP_TEST_READER must name one exact reader")
	}

	for _, mode := range []struct {
		name    string
		options []client.Option
	}{
		{name: "default"},
		{name: "extended", options: []client.Option{client.WithExtendedLength()}},
	} {
		t.Run("typed_"+mode.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			device, maximum := openHardwareChallengeDevice(t, ctx, reader, mode.options...)
			for _, length := range []uint32{1, 16, 128, 255, 256, 257} {
				t.Run(strconv.Itoa(int(length)), func(t *testing.T) {
					if length > uint32(maximum) {
						t.Skipf("requested %d bytes exceeds announced maximum %d", length, maximum)
					}

					data, err := device.GetChallenge(ctx, length)
					t.Logf("GetChallenge(%d): response length=%d error=%v", length, len(data), err)

					if err != nil {
						t.Fatal(err)
					}

					if uint32(len(data)) != length {
						t.Errorf("response length=%d, want %d", len(data), length)
					}
				})
			}
		})
	}

	for _, probe := range []struct {
		name     string
		encoding baseiso7816.Encoding
	}{
		{name: "raw_short_256", encoding: baseiso7816.EncodingShort},
		{name: "raw_extended_256", encoding: baseiso7816.EncodingExtended},
	} {
		t.Run(probe.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			device, maximum := openHardwareChallengeDevice(t, ctx, reader)
			if maximum < 256 {
				t.Logf("diagnostic request exceeds announced maximum %d", maximum)
			}

			response, err := device.Exchange(ctx, baseiso7816.Command{
				INS: 0x84, Le: 256, Encoding: probe.encoding,
			})
			t.Logf("raw 256: response length=%d status=%s error=%v", len(response.Data), response.Status, err)

			if err != nil {
				t.Fatal(err)
			}

			if err := response.APDUError(); err != nil {
				// Short Le=00 and lengths above the announced maximum are
				// interoperability probes, not requirements on this card.
				t.Skipf("card rejects raw 256-byte probe: %v", err)
			}

			if len(response.Data) != 256 {
				t.Errorf("response length=%d, want 256", len(response.Data))
			}
		})
	}
}

func openHardwareChallengeDevice(t testing.TB, ctx context.Context, reader string, options ...client.Option) (*card.Device, uint16) {
	t.Helper()

	native, err := nativepcsc.Open(reader,
		nativepcsc.WithShareMode(nativepcsc.ShareModeExclusive),
		nativepcsc.WithDisconnectDisposition(nativepcsc.DispositionLeaveCard),
	)
	if err != nil {
		t.Fatal(err)
	}

	closeConnection := native.Close

	t.Cleanup(func() {
		if err := closeConnection(); err != nil {
			t.Error(err)
		}
	})

	connection, err := openpgpiso7816.Open(ctx, &challengeTraceCard{Card: native, t: t})
	if err != nil {
		t.Fatal(err)
	}

	device := card.New(connection, options...)
	closeConnection = device.Close

	application, err := device.GetApplicationRelatedData(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if application.ExtendedCapabilities == nil || !application.ExtendedCapabilities.GetChallenge {
		t.Skip("card does not announce GET CHALLENGE support")
	}

	t.Logf("GET CHALLENGE announced maximum=%d", application.ExtendedCapabilities.MaxChallengeLength)

	return device, application.ExtendedCapabilities.MaxChallengeLength
}

type challengeTraceCard struct {
	*nativepcsc.Card
	t testing.TB
}

func (c *challengeTraceCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	response, err := c.Card.Transmit(ctx, apdu)
	if len(response) >= 2 {
		c.t.Logf("transmitted APDU=%x response length=%d status=%02x%02x error=%v",
			apdu, len(response)-2, response[len(response)-2], response[len(response)-1], err)
	} else {
		c.t.Logf("transmitted APDU=%x response length=%d missing status word error=%v", apdu, len(response), err)
	}

	return response, err
}
