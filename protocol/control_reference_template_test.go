package protocol_test

import (
	"bytes"
	"testing"

	"github.com/telesma-app/openpgp/protocol"
)

func TestControlReferenceTemplateBytes(t *testing.T) {
	for _, tt := range []struct {
		name     string
		template protocol.ControlReferenceTemplate
		want     []byte
	}{
		{
			name:     "short signature",
			template: protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag},
			want:     []byte{0xb6, 0},
		},
		{
			name:     "short decryption",
			template: protocol.ControlReferenceTemplate{Tag: protocol.ConfidentialityTemplateTag},
			want:     []byte{0xb8, 0},
		},
		{
			name:     "short authentication",
			template: protocol.ControlReferenceTemplate{Tag: protocol.AuthenticationTemplateTag},
			want:     []byte{0xa4, 0},
		},
		{
			name:     "extended signature",
			template: protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag, KeyReference: protocol.SignatureKeyReference},
			want:     []byte{0xb6, 3, 0x84, 1, 1},
		},
		{
			name:     "extended decryption",
			template: protocol.ControlReferenceTemplate{Tag: protocol.ConfidentialityTemplateTag, KeyReference: protocol.DecryptionKeyReference},
			want:     []byte{0xb8, 3, 0x84, 1, 2},
		},
		{
			name:     "extended authentication",
			template: protocol.ControlReferenceTemplate{Tag: protocol.AuthenticationTemplateTag, KeyReference: protocol.AuthenticationKeyReference},
			want:     []byte{0xa4, 3, 0x84, 1, 3},
		},
		{
			name:     "reserved Yubico attestation",
			template: protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag, KeyReference: protocol.AttestationKeyReference},
			want:     []byte{0xb6, 3, 0x84, 1, 0x81},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.template.Bytes()

			if !bytes.Equal(got, tt.want) {
				t.Errorf("template = %x, want %x", got, tt.want)
			}
		})
	}
}
