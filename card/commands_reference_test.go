package card

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestReferenceStatusReadsCardState(t *testing.T) {
	for _, test := range []struct {
		name      string
		reference protocol.PasswordReference
		wire      []byte
		status    iso7816.StatusWord
		want      client.ReferenceStatus
	}{
		{
			name: "verified PW3", reference: protocol.PW3, wire: []byte{0, 0x20, 0, 0x83}, status: 0x9000,
			want: client.ReferenceStatus{Verified: true},
		},
		{
			name: "unverified PW1", reference: protocol.PW1Sign, wire: []byte{0, 0x20, 0, 0x81}, status: 0x63c3,
			want: client.ReferenceStatus{Retries: 3},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls, closes int

			d := New(&exchangeTransport{
				exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
					calls++

					raw, err := command.MarshalBinary()
					if err != nil {
						t.Fatal(err)
					}

					if !bytes.Equal(raw, test.wire) {
						t.Errorf("command = %x, want %x", raw, test.wire)
					}

					return iso7816.Response{Status: test.status}, nil
				},
				close: func() error { closes++; return nil },
			})

			t.Cleanup(func() { _ = d.Close() })

			got, err := d.ReferenceStatus(t.Context(), test.reference)
			if err != nil || got != test.want {
				t.Errorf("ReferenceStatus = %+v, %v; want %+v, nil", got, err, test.want)
			}

			if calls != 1 || closes != 0 {
				t.Errorf("exchanges=%d closes=%d, want 1 and 0", calls, closes)
			}
		})
	}
}

func TestReferenceDataMaintenancePreservesInputs(t *testing.T) {
	for _, operation := range []struct {
		name           string
		credential     string
		wire           []byte
		retryReference protocol.PasswordReference
		call           func(context.Context, *Device, []byte, []byte) error
	}{
		{
			name: "change PW1", credential: "123456", retryReference: protocol.PW1Sign,
			wire: []byte{0, 0x24, 0, 0x81, 12, '1', '2', '3', '4', '5', '6', '6', '5', '4', '3', '2', '1'},
			call: func(ctx context.Context, d *Device, current, replacement []byte) error {
				return d.ChangeReferenceData(ctx, protocol.PW1Sign, current, replacement)
			},
		},
		{
			name: "change PW3", credential: "12345678", retryReference: protocol.PW3,
			wire: []byte{0, 0x24, 0, 0x83, 14, '1', '2', '3', '4', '5', '6', '7', '8', '6', '5', '4', '3', '2', '1'},
			call: func(ctx context.Context, d *Device, current, replacement []byte) error {
				return d.ChangeReferenceData(ctx, protocol.PW3, current, replacement)
			},
		},
		{
			name: "reset PW1", credential: "12345678", retryReference: 0,
			wire: []byte{0, 0x2c, 0, 0x81, 14, '1', '2', '3', '4', '5', '6', '7', '8', '6', '5', '4', '3', '2', '1'},
			call: func(ctx context.Context, d *Device, resettingCode, replacement []byte) error {
				return d.ResetRetryCounter(ctx, resettingCode, replacement)
			},
		},
	} {
		t.Run(operation.name, func(t *testing.T) {
			for _, test := range []struct {
				name   string
				status iso7816.StatusWord
			}{
				{name: "success", status: 0x9000},
				{name: "retry failure", status: 0x63c2},
			} {
				t.Run(test.name, func(t *testing.T) {
					credential := []byte(operation.credential + " reserved")
					replacement := []byte("654321 reserved")
					credentialBefore := slices.Clone(credential)
					replacementBefore := slices.Clone(replacement)

					var calls, closes int

					d := New(&exchangeTransport{
						exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
							calls++

							raw, err := command.MarshalBinary()
							if err != nil {
								t.Fatal(err)
							}

							if !bytes.Equal(raw, operation.wire) {
								t.Errorf("command = %x, want %x", raw, operation.wire)
							}

							return iso7816.Response{Status: test.status}, nil
						},
						close: func() error { closes++; return nil },
					})

					t.Cleanup(func() { _ = d.Close() })

					err := operation.call(t.Context(), d, credential[:len(operation.credential)], replacement[:6])
					if test.status == 0x63c2 {
						var retry *client.ReferenceDataError
						if !errors.As(err, &retry) || retry.Reference != operation.retryReference || retry.Retries != 2 || retry.Status != 0x63c2 {
							t.Errorf("error = %v, want reference %02x, 2 retries and status 63c2", err, byte(operation.retryReference))
						}

						var apdu *iso7816.APDUError
						if !errors.As(err, &apdu) || apdu.StatusWord() != 0x63c2 {
							t.Errorf("error = %v, want APDU error 63c2", err)
						}
					} else if err != nil {
						t.Error(err)
					}

					if !bytes.Equal(credential, credentialBefore) || !bytes.Equal(replacement, replacementBefore) {
						t.Error("reference maintenance changed borrowed input storage")
					}

					if calls != 1 || closes != 0 {
						t.Errorf("exchanges=%d closes=%d, want 1 and 0", calls, closes)
					}
				})
			}
		})
	}
}

func TestReferenceCommandLifecycle(t *testing.T) {
	for _, operation := range []struct {
		name string
		call func(context.Context, *Device) error
	}{
		{
			name: "ReferenceStatus",
			call: func(ctx context.Context, d *Device) error {
				_, err := d.ReferenceStatus(ctx, protocol.PW1Sign)
				return err
			},
		},
		{
			name: "ChangeReferenceData",
			call: func(ctx context.Context, d *Device) error {
				return d.ChangeReferenceData(ctx, protocol.PW1Sign, []byte("123456"), []byte("654321"))
			},
		},
		{
			name: "ResetRetryCounter",
			call: func(ctx context.Context, d *Device) error {
				return d.ResetRetryCounter(ctx, []byte("12345678"), []byte("654321"))
			},
		},
	} {
		t.Run(operation.name, func(t *testing.T) {
			checkOperationLifecycle(t, nil, operation.call)
		})
	}
}
