package protocol

// FileID identifies a file under the MF (Sec. 4.1), addressed by GET DATA with odd INS
// (Sec. 7.2.6).
type FileID uint16

const (
	DirectoryFile FileID = 0x2f00
	ATRInfoFile   FileID = 0x2f01
)
