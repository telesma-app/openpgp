package card

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"testing/synctest"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

func TestGetDataWithAuthenticationKeepsVerificationAndReadTogether(t *testing.T) {
	for _, tt := range []struct {
		name      string
		object    protocol.Object
		reference protocol.PasswordReference
	}{
		{"private use 3", protocol.PrivateUse3Object, protocol.PW1},
		{"private use 4", protocol.PrivateUse4Object, protocol.PW3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				verifyStarted := make(chan struct{})
				continueVerify := make(chan struct{})

				defer func() {
					select {
					case <-continueVerify:
					default:
						close(continueVerify)
					}
				}()

				password := []byte("encoded password")

				var sequence [][3]byte

				d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
					sequence = append(sequence, [3]byte{command.INS, command.P1, command.P2})
					if command.INS == byte(protocol.Verify) && command.P1 == 0 {
						if !bytes.Equal(command.Data, []byte("encoded password")) {
							t.Errorf("VERIFY data = %q, want encoded password", command.Data)
						}

						close(verifyStarted)
						<-continueVerify
					}

					if command.INS == byte(protocol.GetData) && command.P1 == byte(tt.object>>8) && command.P2 == byte(tt.object) {
						if !bytes.Equal(password, make([]byte, len(password))) {
							t.Error("password was not cleared before reading private data")
						}

						return success([]byte("private value")), nil
					}

					return success(nil), nil
				}})

				t.Cleanup(func() { _ = d.Close() })

				completed := make(chan error, 1)

				go func() {
					data, err := d.GetDataWithAuthentication(t.Context(), tt.object, tt.reference, func(ctx context.Context) ([]byte, error) {
						// Password sources may inspect the device before the gate.
						if _, err := d.GetData(ctx, protocol.KDFObject); err != nil {
							return nil, err
						}

						return password, nil
					})
					if err == nil && string(data) != "private value" {
						t.Errorf("data = %q, want private value", data)
					}

					completed <- err
				}()

				receive(t, verifyStarted, "VERIFY starting")

				reset := make(chan error, 1)
				go func() { reset <- d.ResetSecurityStatus(t.Context(), tt.reference) }()

				synctest.Wait()

				if len(sequence) != 2 {
					t.Errorf("commands during VERIFY = %x, want source read and VERIFY", sequence)
				}

				close(continueVerify)

				if err := receive(t, completed, "private data read"); err != nil {
					t.Fatal(err)
				}

				if err := receive(t, reset, "queued security status reset"); err != nil {
					t.Fatal(err)
				}

				want := [][3]byte{
					{0xca, 0, 0xf9},
					{0x20, 0, byte(tt.reference)},
					{0xca, byte(tt.object >> 8), byte(tt.object)},
					{0x20, 0xff, byte(tt.reference)},
				}
				if !slices.Equal(sequence, want) {
					t.Errorf("sequence = %x, want %x", sequence, want)
				}
			})
		})
	}
}
