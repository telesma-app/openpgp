package protocol_test

import (
	"bytes"
	"testing"

	"github.com/telesma-app/openpgp/protocol"
)

func TestEncodePWStatusBytesUpdate(t *testing.T) {
	for _, test := range []struct {
		name   string
		update protocol.PWStatusBytesUpdate
		want   []byte
	}{
		{name: "one signature", want: []byte{0}},
		{
			name:   "multiple signatures",
			update: protocol.PWStatusBytesUpdate{PW1ValidForMultipleSignatures: true},
			want:   []byte{1},
		},
		{
			name: "UTF8 or derived format",
			update: protocol.PWStatusBytesUpdate{LengthAndFormat: &protocol.PWLengthAndFormat{
				PW1MaxLength: 32, ResettingCodeMaxLength: 64, PW3MaxLength: 127,
			}},
			want: []byte{0, 0x20, 0x40, 0x7f},
		},
		{
			name: "PIN block 2",
			update: protocol.PWStatusBytesUpdate{
				PW1ValidForMultipleSignatures: true,
				LengthAndFormat: &protocol.PWLengthAndFormat{
					PW1MaxLength: 32, ResettingCodeMaxLength: 32, PW3MaxLength: 64,
					PW1PINBlock2: true, PW3PINBlock2: true,
				},
			},
			want: []byte{1, 0xa0, 0x20, 0xc0},
		},
		{
			name: "independent format bits and complete RC byte",
			update: protocol.PWStatusBytesUpdate{LengthAndFormat: &protocol.PWLengthAndFormat{
				PW1MaxLength: 127, ResettingCodeMaxLength: 255, PW3MaxLength: 64,
				PW1PINBlock2: true,
			}},
			want: []byte{0, 0xff, 0xff, 0x40},
		},
		{
			name: "explicit zero group remains four bytes",
			update: protocol.PWStatusBytesUpdate{
				PW1ValidForMultipleSignatures: true, LengthAndFormat: &protocol.PWLengthAndFormat{},
			},
			want: []byte{1, 0, 0, 0},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := protocol.EncodePWStatusBytesUpdate(test.update)

			if !bytes.Equal(got, test.want) {
				t.Errorf("C4 update = %x, want %x", got, test.want)
			}
		})
	}
}

func TestPWStatusBytesUpdatePreservesReadLimits(t *testing.T) {
	// GET returns seven bytes. PUT carries only the first four; the final
	// three retry counters are not writable (OpenPGP Card 3.4.1, Sec. 4.4.2).
	data := []byte{1, 0xa0, 0xfe, 0xc0, 3, 2, 1}

	status, err := protocol.ParsePWStatusBytes(data)
	if err != nil {
		t.Fatal(err)
	}

	format := protocol.PWLengthAndFormat{
		PW1MaxLength: status.PW1MaxLength, ResettingCodeMaxLength: status.ResettingCodeMaxLength,
		PW3MaxLength: status.PW3MaxLength, PW1PINBlock2: false, PW3PINBlock2: status.PW3PINBlock2,
	}
	update := protocol.PWStatusBytesUpdate{PW1ValidForMultipleSignatures: true, LengthAndFormat: &format}

	encoded := protocol.EncodePWStatusBytesUpdate(update)
	if !bytes.Equal(encoded, []byte{1, 0x20, 0xfe, 0xc0}) {
		t.Errorf("updated C4 = %x, want 0120fec0 without retry counters", encoded)
	}

	clear(encoded)

	if format.PW1MaxLength != 32 || format.ResettingCodeMaxLength != 254 || format.PW3MaxLength != 64 || format.PW1PINBlock2 || !format.PW3PINBlock2 {
		t.Errorf("encoding changed the supplied format: %+v", format)
	}

	if !bytes.Equal(data, []byte{1, 0xa0, 0xfe, 0xc0, 3, 2, 1}) {
		t.Errorf("encoding changed the GET response: %x", data)
	}
}
