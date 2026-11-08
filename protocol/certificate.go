package protocol

// CardholderCertificates holds the three standard certificates as opaque bytes.
// Contents may be empty; the caller handles parsing and trust.
type CardholderCertificates struct {
	Authentication []byte
	Decryption     []byte
	Signature      []byte
}
