package protocol

import "fmt"

// KeyStatus is the status byte in Key Information (Sec. 4.4.3.8).
type KeyStatus byte

const (
	KeyStatusNotPresent KeyStatus = 0
	KeyStatusGenerated  KeyStatus = 1
	KeyStatusImported   KeyStatus = 2
)

// KeyInformation is a DO DE entry (Sec. 4.4.3.8), using numeric key references.
// Status is 0 absent, 1 generated, or 2 imported; unknown values are retained.
// The reported status does not establish key provenance.
type KeyInformation struct {
	Reference KeyReference
	Status    KeyStatus
}

func ParseKeyInformation(data []byte) ([]KeyInformation, error) {
	if len(data) < 6 || len(data)%2 != 0 {
		return nil, fmt.Errorf("%w: key information length", ErrInvalidResponse)
	}

	keys := make([]KeyInformation, 0, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		keys = append(keys, KeyInformation{Reference: KeyReference(data[i]), Status: KeyStatus(data[i+1])})
	}

	return keys, nil
}
