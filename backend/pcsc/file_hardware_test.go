package pcsc_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	baseiso7816 "github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
	openpgpiso7816 "github.com/telesma-app/openpgp/transport/iso7816"
	nativepcsc "github.com/telesma-app/pcsc"
)

// TestHardwareReadFile reads optional EFs after a session reset, before SELECT.
// It uses no PINs, writes or factory reset. Diagnostics omit file contents.
func TestHardwareReadFile(t *testing.T) {
	if os.Getenv("OPENPGP_TEST") != "1" {
		t.Skip("set OPENPGP_TEST=1 to read optional EF files on a selected card")
	}

	reader := os.Getenv("OPENPGP_TEST_READER")
	if reader == "" {
		t.Fatal("OPENPGP_TEST_READER must name one exact reader")
	}

	for _, test := range []struct {
		name string
		file protocol.FileID
	}{
		{name: "directory", file: protocol.DirectoryFile},
		{name: "atr_info", file: protocol.ATRInfoFile},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

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

			if _, err := native.Reconnect(ctx, nativepcsc.ShareModeExclusive,
				nativepcsc.ProtocolT0|nativepcsc.ProtocolT1, nativepcsc.DispositionResetCard); err != nil {
				t.Fatalf("reset card session before file read: %v", err)
			}

			connection := openpgpiso7816.New(native)
			closeConnection = connection.Close
			c := client.NewClient(&fileReadTraceAPDU{connection: connection, t: t, file: test.file})

			_, fileErr := c.GetDataOdd(ctx, test.file)

			if err := c.Select(ctx); err != nil {
				t.Fatal(errors.Join(fileErr, fmt.Errorf("select OpenPGP after file read: %w", err)))
			}

			if _, err := c.GetApplicationRelatedData(ctx); err != nil {
				t.Fatal(errors.Join(fileErr, fmt.Errorf("read OpenPGP metadata after file read: %w", err)))
			}

			if fileErr != nil {
				var apdu *baseiso7816.APDUError
				if errors.As(fileErr, &apdu) {
					switch apdu.StatusWord() {
					case 0x6a81, 0x6a82, 0x6a86, 0x6a88, 0x6d00:
						t.Skipf("optional file %04x unavailable; OpenPGP connection remains usable: %v", uint16(test.file), fileErr)
					}
				}

				t.Fatal(fileErr)
			}
		})
	}
}

type fileReadTraceAPDU struct {
	connection *openpgpiso7816.Transport
	t          testing.TB
	file       protocol.FileID
}

func (trace *fileReadTraceAPDU) Exchange(ctx context.Context, command baseiso7816.Command) (baseiso7816.Response, error) {
	response, err := trace.connection.Exchange(ctx, command)
	if command.INS == byte(protocol.GetDataOdd) {
		if err != nil {
			trace.t.Logf("file=%04x response length=%d status=unavailable error=%v", uint16(trace.file), len(response.Data), err)
		} else {
			trace.t.Logf("file=%04x response length=%d status=%s error=%v", uint16(trace.file), len(response.Data), response.Status, err)
		}
	}

	return response, err
}
