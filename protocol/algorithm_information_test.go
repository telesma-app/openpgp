package protocol_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/telesma-app/openpgp/protocol"
)

// OpenPGP Card 3.4.1, Sec. 4.4.3.11 defines an ordered list of complete
// algorithm-attribute DOs, including repeated tags and proprietary keys.
// Sec. 4.4.4 also permits the long-form 81 06 length used by the last entry.
func TestAlgorithmInformation(t *testing.T) {
	const body = "c106010800002000c106010c00002003" +
		"c209122a8648ce3d030107c20a122a8648ce3d030107ff" +
		"c306132b81040022da0463010203c18106010800002000"
	for _, tt := range []struct {
		name string
		data string
	}{
		{name: "child objects", data: body},
		{name: "FA template", data: "fa3e" + body},
		{name: "long FA length", data: "fa813e" + body},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := algorithmAttributesHex(t, tt.data)

			got, err := protocol.ParseAlgorithmInformation(data)
			if err != nil {
				t.Fatal(err)
			}

			want := []struct {
				object    protocol.Object
				algorithm protocol.Algorithm
				raw       string
			}{
				{object: protocol.SignatureAlgorithmAttributesObject, algorithm: protocol.RSA, raw: "010800002000"},
				{object: protocol.SignatureAlgorithmAttributesObject, algorithm: protocol.RSA, raw: "010c00002003"},
				{object: protocol.DecryptionAlgorithmAttributesObject, algorithm: protocol.ECDH, raw: "122a8648ce3d030107"},
				{object: protocol.DecryptionAlgorithmAttributesObject, algorithm: protocol.ECDH, raw: "122a8648ce3d030107ff"},
				{object: protocol.AuthenticationAlgorithmAttributesObject, algorithm: protocol.ECDSA, raw: "132b81040022"},
				{object: protocol.AttestationAlgorithmAttributesObject, algorithm: 0x63, raw: "63010203"},
				{object: protocol.SignatureAlgorithmAttributesObject, algorithm: protocol.RSA, raw: "010800002000"},
			}
			if len(got) != len(want) {
				t.Fatalf("entries = %d, want %d", len(got), len(want))
			}

			for i, entry := range got {
				if entry.Object != want[i].object || entry.Attributes.Algorithm != want[i].algorithm ||
					hex.EncodeToString(entry.Attributes.Raw) != want[i].raw {
					t.Errorf("entry %d = %+v, raw %x; want object %04x algorithm %02x raw %s",
						i, entry, entry.Attributes.Raw, want[i].object, want[i].algorithm, want[i].raw)
				}

				if encoded := protocol.EncodeAlgorithmAttributes(entry.Attributes); hex.EncodeToString(encoded) != want[i].raw {
					t.Errorf("entry %d PUT DATA value = %x, want %s", i, encoded, want[i].raw)
				}
			}

			if got[0].Attributes.ModulusBits != 2048 || got[0].Attributes.ExponentBits != 32 ||
				got[1].Attributes.ModulusBits != 3072 || got[1].Attributes.ImportFormat != protocol.ImportFormatCRTWithModulus {
				t.Errorf("RSA alternatives = %+v / %+v", got[0].Attributes, got[1].Attributes)
			}

			if got[2].Attributes.ImportFormat != protocol.ImportFormatStandard ||
				got[3].Attributes.ImportFormat != protocol.ImportFormatStandardWithPublicKey ||
				!bytes.Equal(got[2].Attributes.CurveOID, got[3].Attributes.CurveOID) ||
				hex.EncodeToString(got[2].Attributes.CurveOID) != "2a8648ce3d030107" {
				t.Errorf("EC import variants = %+v / %+v", got[2].Attributes, got[3].Attributes)
			}

			if hex.EncodeToString(data) != tt.data {
				t.Error("parsing changed the borrowed response")
			}
		})
	}
}

func TestAlgorithmInformationRetainsProprietaryMetadataAndOrder(t *testing.T) {
	const raw = "c30a132b0601040183b20301df200463010203c106010800002000"

	got, err := protocol.ParseAlgorithmInformation(algorithmAttributesHex(t, raw))
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 3 {
		t.Fatalf("entries = %d, want 3", len(got))
	}

	if got[0].Object != protocol.AuthenticationAlgorithmAttributesObject || got[0].Attributes.Algorithm != protocol.ECDSA ||
		hex.EncodeToString(got[0].Attributes.CurveOID) != "2b0601040183b20301" {
		t.Errorf("unknown curve entry = %+v", got[0])
	}

	if got[1].Object != 0xdf20 || got[1].Attributes.Algorithm != 0x63 ||
		hex.EncodeToString(got[1].Attributes.Raw) != "63010203" {
		t.Errorf("proprietary entry = %+v", got[1])
	}

	if got[2].Object != protocol.SignatureAlgorithmAttributesObject || got[2].Attributes.Algorithm != protocol.RSA {
		t.Errorf("last signature entry = %+v", got[2])
	}
}

func TestAlgorithmInformationEmpty(t *testing.T) {
	for _, data := range [][]byte{nil, {}, {0xfa, 0}} {
		got, err := protocol.ParseAlgorithmInformation(data)
		if err != nil || len(got) != 0 {
			t.Errorf("empty information %x = %+v, %v", data, got, err)
		}
	}
}

func TestAlgorithmInformationMalformedResponse(t *testing.T) {
	for _, tt := range []struct {
		name string
		data string
	}{
		{name: "missing outer length", data: "fa"},
		{name: "truncated outer value", data: "fa08c1060108000020"},
		{name: "trailing outer data", data: "fa00c106010800002000"},
		{name: "indefinite outer length", data: "fa80c1060108000020000000"},
		{name: "missing child length", data: "c1"},
		{name: "truncated child length", data: "c181"},
		{name: "truncated child value", data: "c1060108000020"},
		{name: "empty attributes", data: "c100"},
		{name: "trailing RSA attribute byte", data: "c10701080000200000"},
		{name: "unfinished EC OID", data: "c303132b81"},
		{name: "object exceeds P1 P2", data: "5f81010163"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := protocol.ParseAlgorithmInformation(algorithmAttributesHex(t, tt.data))
			if !errors.Is(err, protocol.ErrInvalidResponse) {
				t.Errorf("malformed information %s: error = %v", tt.data, err)
			}
		})
	}
}
