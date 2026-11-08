package protocol

// Sec. 4.3: user-verification references.

// PasswordReference selects a password and its authorized operation. PW1Sign
// and PW1 share the same password and retry counter, but separate security status.
type PasswordReference byte

const (
	PW1Sign PasswordReference = 0x81
	PW1     PasswordReference = 0x82
	PW3     PasswordReference = 0x83
)
