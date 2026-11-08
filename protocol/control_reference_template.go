package protocol

// Sec. 4.4.3.12: private-key Control Reference Templates in SIG, DEC, AUT order.

// ControlReferenceTemplateTag identifies a cryptographic function's Control
// Reference Template. KeyReference identifies the key assigned to that function.
type ControlReferenceTemplateTag byte

const (
	DigitalSignatureTemplateTag ControlReferenceTemplateTag = 0xb6
	ConfidentialityTemplateTag  ControlReferenceTemplateTag = 0xb8
	AuthenticationTemplateTag   ControlReferenceTemplateTag = 0xa4
)

// KeyReference is a numeric private-key reference used by extended Control
// Reference Templates, Key Information (DO DE), and MANAGE SECURITY ENVIRONMENT.
// MSE permits only DecryptionKeyReference and AuthenticationKeyReference.
type KeyReference byte

const (
	SignatureKeyReference      KeyReference = 1
	DecryptionKeyReference     KeyReference = 2
	AuthenticationKeyReference KeyReference = 3

	// AttestationKeyReference is reserved for Yubico's attestation key.
	// Its availability and supported operations are vendor-specific.
	AttestationKeyReference KeyReference = 0x81
)

// ControlReferenceTemplate addresses an asymmetric key (Secs. 7.2.14 and
// 4.4.3.12). A zero KeyReference selects the short form, whose default key is
// determined by Tag. A nonzero KeyReference selects the extended form.
type ControlReferenceTemplate struct {
	Tag          ControlReferenceTemplateTag
	KeyReference KeyReference
}

// Bytes returns the template's BER-TLV encoding.
func (k ControlReferenceTemplate) Bytes() []byte {
	if k.KeyReference == 0 {
		return []byte{byte(k.Tag), 0}
	}

	return []byte{byte(k.Tag), 3, 0x84, 1, byte(k.KeyReference)}
}
