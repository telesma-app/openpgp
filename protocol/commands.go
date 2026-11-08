package protocol

import "github.com/telesma-app/iso7816"

// Sec. 7.2: instructions follow the command descriptions in specification order.

// Instruction identifies an OpenPGP Card command.
type Instruction byte

const (
	Select                    Instruction = 0xa4
	Verify                    Instruction = 0x20
	ChangeReferenceData       Instruction = 0x24
	ResetRetryCounter         Instruction = 0x2c
	SelectData                Instruction = 0xa5
	GetData                   Instruction = 0xca
	GetDataOdd                Instruction = 0xcb
	GetNextData               Instruction = 0xcc
	PutData                   Instruction = 0xda
	PutDataOdd                Instruction = 0xdb
	PerformSecurityOperation  Instruction = 0x2a
	InternalAuthenticate      Instruction = 0x88
	GenerateAsymmetricKeyPair Instruction = 0x47
	GetChallenge              Instruction = 0x84
	TerminateDF               Instruction = 0xe6
	ActivateFile              Instruction = 0x44
	ManageSecurityEnvironment Instruction = 0x22
)

// SelectCommand selects the OpenPGP application by its six-byte AID prefix.
// Possible FCI response data is not needed by the application (Sec. 7.2.1).
func SelectCommand() iso7816.Command {
	return iso7816.Command{
		INS: byte(Select), P1: 0x04,
		Data: []byte{0xd2, 0x76, 0x00, 0x01, 0x24, 0x01},
		Le:   256, Encoding: iso7816.EncodingShort,
	}
}
