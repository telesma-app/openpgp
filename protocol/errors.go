package protocol

import "errors"

var (
	ErrInvalidResponse      = errors.New("openpgp: invalid response")
	ErrUnsupportedAlgorithm = errors.New("openpgp: unsupported algorithm")
	ErrKeyMismatch          = errors.New("openpgp: key does not match algorithm attributes")
)
