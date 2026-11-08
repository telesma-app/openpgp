package protocol_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/telesma-app/openpgp/protocol"
)

// Values follow OpenPGP Card 3.4.1, Sec. 4.4.3.9. Attribute values contain the
// algorithm ID and binary parameters, without an outer C1/C2/C3 or OID TLV:
// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf
func TestEncodeAlgorithmAttributes(t *testing.T) {
	for _, tt := range []struct {
		name       string
		attributes protocol.AlgorithmAttributes
		want       string
	}{
		{
			name: "RSA standard",
			attributes: protocol.AlgorithmAttributes{
				Algorithm: protocol.RSA, ModulusBits: 2048, ExponentBits: 32,
				ImportFormat: protocol.ImportFormatStandard,
			},
			want: "010800002000",
		},
		{
			name: "RSA standard with modulus",
			attributes: protocol.AlgorithmAttributes{
				Algorithm: protocol.RSA, ModulusBits: 2048, ExponentBits: 32,
				ImportFormat: protocol.ImportFormatStandardWithModulus,
			},
			want: "010800002001",
		},
		{
			name: "RSA CRT",
			attributes: protocol.AlgorithmAttributes{
				Algorithm: protocol.RSA, ModulusBits: 2048, ExponentBits: 32,
				ImportFormat: protocol.ImportFormatCRT,
			},
			want: "010800002002",
		},
		{
			name: "RSA CRT with modulus",
			attributes: protocol.AlgorithmAttributes{
				Algorithm: protocol.RSA, ModulusBits: 2048, ExponentBits: 32,
				ImportFormat: protocol.ImportFormatCRTWithModulus,
			},
			want: "010800002003",
		},
		{
			name: "ECDSA P256 private key",
			attributes: protocol.AlgorithmAttributes{
				Algorithm: protocol.ECDSA, CurveOID: algorithmAttributesHex(t, "2a8648ce3d030107"),
			},
			want: "132a8648ce3d030107",
		},
		{
			name: "ECDSA P256 with public key",
			attributes: protocol.AlgorithmAttributes{
				Algorithm: protocol.ECDSA, CurveOID: algorithmAttributesHex(t, "2a8648ce3d030107"),
				ImportFormat: protocol.ImportFormatStandardWithPublicKey,
			},
			want: "132a8648ce3d030107ff",
		},
		{
			name: "ECDH P384 private key",
			attributes: protocol.AlgorithmAttributes{
				Algorithm: protocol.ECDH, CurveOID: algorithmAttributesHex(t, "2b81040022"),
			},
			want: "122b81040022",
		},
		{
			name: "ECDH P384 with public key",
			attributes: protocol.AlgorithmAttributes{
				Algorithm: protocol.ECDH, CurveOID: algorithmAttributesHex(t, "2b81040022"),
				ImportFormat: protocol.ImportFormatStandardWithPublicKey,
			},
			want: "122b81040022ff",
		},
		{
			name: "EdDSA private key",
			attributes: protocol.AlgorithmAttributes{
				Algorithm: protocol.EdDSA, CurveOID: algorithmAttributesHex(t, "2b06010401da470f01"),
			},
			want: "162b06010401da470f01",
		},
		{
			name: "EdDSA with public key",
			attributes: protocol.AlgorithmAttributes{
				Algorithm: protocol.EdDSA, CurveOID: algorithmAttributesHex(t, "2b06010401da470f01"),
				ImportFormat: protocol.ImportFormatStandardWithPublicKey,
			},
			want: "162b06010401da470f01ff",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			curve := bytes.Clone(tt.attributes.CurveOID)

			got := protocol.EncodeAlgorithmAttributes(tt.attributes)

			if hex.EncodeToString(got) != tt.want {
				t.Errorf("encoded attributes = %x, want %s", got, tt.want)
			}

			clear(got)

			if !bytes.Equal(tt.attributes.CurveOID, curve) {
				t.Error("encoding or clearing the result changed the borrowed curve OID")
			}
		})
	}
}

func TestEncodeAlgorithmAttributesUsesEditedFields(t *testing.T) {
	for _, tt := range []struct {
		name string
		raw  string
		edit func(*protocol.AlgorithmAttributes)
		want string
	}{
		{
			name: "RSA sizes and format", raw: "010800002000",
			edit: func(attributes *protocol.AlgorithmAttributes) {
				attributes.ModulusBits = 3072
				attributes.ExponentBits = 64
				attributes.ImportFormat = protocol.ImportFormatCRTWithModulus
			},
			want: "010c00004003",
		},
		{
			name: "EC family curve and format", raw: "132a8648ce3d030107ff",
			edit: func(attributes *protocol.AlgorithmAttributes) {
				attributes.Algorithm = protocol.ECDH
				attributes.CurveOID = []byte{0x2b, 0x81, 0x04, 0x00, 0x22}
				attributes.ImportFormat = protocol.ImportFormatStandard
			},
			want: "122b81040022",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := algorithmAttributesHex(t, tt.raw)

			attributes, err := protocol.ParseAlgorithmAttributes(data)
			if err != nil {
				t.Fatal(err)
			}

			tt.edit(&attributes)

			got := protocol.EncodeAlgorithmAttributes(attributes)

			if hex.EncodeToString(got) != tt.want {
				t.Errorf("edited attributes = %x, want %s", got, tt.want)
			}

			clear(got)

			if hex.EncodeToString(data) != tt.raw || !bytes.Equal(attributes.Raw, data) {
				t.Error("encoding edited fields changed the original response")
			}
		})
	}
}

func TestEncodeUnknownAlgorithmAttributesPreservesRawValue(t *testing.T) {
	data := []byte{0x63, 0x01, 0xff, 0x00, 0x7f}

	attributes, err := protocol.ParseAlgorithmAttributes(data)
	if err != nil {
		t.Fatal(err)
	}

	got := protocol.EncodeAlgorithmAttributes(attributes)

	if !bytes.Equal(got, []byte{0x63, 0x01, 0xff, 0x00, 0x7f}) {
		t.Errorf("unknown attributes = %x", got)
	}

	clear(got)

	if !bytes.Equal(data, []byte{0x63, 0x01, 0xff, 0x00, 0x7f}) || !bytes.Equal(attributes.Raw, data) {
		t.Error("clearing encoded unknown attributes changed the borrowed response")
	}
}

func algorithmAttributesHex(t testing.TB, encoded string) []byte {
	t.Helper()

	data, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}

	return data
}
