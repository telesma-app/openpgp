package card

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport"
)

func TestMetadataReads(t *testing.T) {
	want := [][]byte{{0, 0xca, 0x5f, 0x52, 0}, {0, 0xca, 0x7f, 0x66, 0}, {0, 0xca, 0x7f, 0x74, 0}}
	responses := [][]byte{
		{0, 0x73, 0, 0, 0xc0, 5, 0x90, 0},
		{0x7f, 0x66, 8, 2, 2, 8, 0, 2, 2, 8, 0},
		{0x7f, 0x74, 3, 0x81, 1, 0x20},
	}

	var calls int

	d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
		raw, err := command.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}

		if calls >= len(want) {
			t.Fatalf("unexpected command = %x", raw)
		}

		if !bytes.Equal(raw, want[calls]) {
			t.Errorf("command = %x, want %x", raw, want[calls])
		}

		response := responses[calls]
		calls++

		return success(response), nil
	}})

	t.Cleanup(func() { _ = d.Close() })

	historical, err := d.GetHistoricalBytes(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if historical.CardCapabilities == nil || !historical.CardCapabilities.CommandChaining ||
		!historical.CardCapabilities.ExtendedLength || historical.CardCapabilities.ExtendedLengthInformationInEFATRInfo ||
		!bytes.Equal(historical.Raw, responses[0]) {
		t.Errorf("historical bytes = %+v", historical)
	}

	lengths, err := d.GetExtendedLengthInformation(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if lengths.MaxCommandAPDULength != 2048 || lengths.MaxResponseAPDULength != 2048 || !bytes.Equal(lengths.Raw, responses[1]) {
		t.Errorf("extended length information = %+v", lengths)
	}

	features, err := d.GetGeneralFeatureManagement(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if features.Features != protocol.GeneralFeatureButton || !bytes.Equal(features.Raw, responses[2]) {
		t.Errorf("general feature management = %+v", features)
	}

	if calls != len(want) {
		t.Errorf("exchanges = %d, want %d", calls, len(want))
	}
}

func TestMetadataReadCancellationAndInvalidation(t *testing.T) {
	for _, operation := range []struct {
		name string
		data []byte
		read func(context.Context, *Device) error
	}{
		{
			name: "historical bytes", data: []byte{0, 0x73, 0, 0, 0xe0, 5, 0x90, 0},
			read: func(ctx context.Context, d *Device) error { _, err := d.GetHistoricalBytes(ctx); return err },
		},
		{
			name: "extended length information", data: []byte{2, 2, 8, 0, 2, 2, 8, 0},
			read: func(ctx context.Context, d *Device) error { _, err := d.GetExtendedLengthInformation(ctx); return err },
		},
		{
			name: "general feature management", data: []byte{0x81, 1, 0x20},
			read: func(ctx context.Context, d *Device) error { _, err := d.GetGeneralFeatureManagement(ctx); return err },
		},
	} {
		for _, invalidation := range []bool{false, true} {
			name := operation.name + "/canceled before I/O"
			if invalidation {
				name = operation.name + "/connection invalidated"
			}

			t.Run(name, func(t *testing.T) {
				var calls, closes int

				d := New(&exchangeTransport{
					exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
						calls++

						if invalidation {
							return iso7816.Response{}, &transport.DeviceInvalidatedError{Err: io.ErrUnexpectedEOF}
						}

						return success(operation.data), nil
					},
					close: func() error { closes++; return nil },
				})

				t.Cleanup(func() { _ = d.Close() })

				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()

				if !invalidation {
					cancel()
				}

				err := operation.read(ctx, d)

				if invalidation {
					var invalidated *transport.DeviceInvalidatedError
					if !errors.As(err, &invalidated) || !errors.Is(err, io.ErrUnexpectedEOF) || calls != 1 || closes != 1 {
						t.Fatalf("invalidated read = %v, exchanges=%d closes=%d", err, calls, closes)
					}

					if err := operation.read(t.Context(), d); !errors.Is(err, io.ErrClosedPipe) || calls != 1 {
						t.Errorf("read after invalidation = %v, exchanges=%d", err, calls)
					}
				} else {
					if !errors.Is(err, context.Canceled) || calls != 0 || closes != 0 {
						t.Fatalf("canceled read = %v, exchanges=%d closes=%d", err, calls, closes)
					}

					if err := operation.read(t.Context(), d); err != nil || calls != 1 || closes != 0 {
						t.Errorf("read after cancellation = %v, exchanges=%d closes=%d", err, calls, closes)
					}
				}
			})
		}
	}
}
