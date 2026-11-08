package protocol

import "fmt"

// Sec. 4.4.1: Security Support Template (7A).

// SecuritySupportTemplate contains the 24-bit count of COMPUTE DIGITAL
// SIGNATURE operations. INTERNAL AUTHENTICATE does not increment this counter.
type SecuritySupportTemplate struct {
	DigitalSignatureCounter uint32
}

func ParseSecuritySupportTemplate(data []byte) (SecuritySupportTemplate, error) {
	data, err := constructedContents(data, 0x7a)
	if err != nil {
		return SecuritySupportTemplate{}, err
	}

	fields, err := objectFields(data)
	if err != nil {
		return SecuritySupportTemplate{}, err
	}

	value := fields[0x93]
	if len(value) != 3 {
		return SecuritySupportTemplate{}, fmt.Errorf("%w: signature counter length", ErrInvalidResponse)
	}

	return SecuritySupportTemplate{DigitalSignatureCounter: uint32(value[0])<<16 | uint32(value[1])<<8 | uint32(value[2])}, nil
}
