package protocol

import (
	"fmt"

	"github.com/telesma-app/bertlv"
)

// AlgorithmInformation is one advertised Algorithm Attributes DO in FA
// (Sec. 4.4.3.11). Object identifies C1, C2, C3 or a proprietary attributes
// object. Attributes and its Raw value borrow the parsed response.
type AlgorithmInformation struct {
	Object     Object
	Attributes AlgorithmAttributes
}

// ParseAlgorithmInformation accepts the complete FA template or its child DOs.
// It preserves the order and repeated objects, including proprietary entries.
// Each entry uses the Algorithm Attributes format; unknown algorithm IDs and
// curve OIDs remain readable without local crypto support. Object tags must
// fit the two-byte GET/PUT DATA address.
func ParseAlgorithmInformation(data []byte) ([]AlgorithmInformation, error) {
	data, err := constructedContents(data, 0xfa)
	if err != nil {
		return nil, err
	}

	var algorithms []AlgorithmInformation

	for len(data) != 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("%w: algorithm information: %v", ErrInvalidResponse, err)
		}

		if tag > 0xffff {
			return nil, fmt.Errorf("%w: algorithm attributes tag %x exceeds the GET/PUT DATA address", ErrInvalidResponse, tag)
		}

		attributes, err := ParseAlgorithmAttributes(value)
		if err != nil {
			return nil, fmt.Errorf("openpgp: algorithm information %04x: %w", tag, err)
		}

		algorithms = append(algorithms, AlgorithmInformation{Object: Object(tag), Attributes: attributes})
		data = rest
	}

	return algorithms, nil
}
