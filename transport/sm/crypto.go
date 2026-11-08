// CBC encryption, CMAC and response decryption in specification order (Sec. 7.5).
package sm

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// encrypt uses the challenge as the CBC IV (OpenPGP Card 3.4.1, Sec. 7.5).
func encrypt(block cipher.Block, iv [aes.BlockSize]byte, plaintext []byte) []byte {
	data := pad(plaintext)
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(data, data)

	return data
}

// cmac applies SP 800-38B with the supplied initial chaining value. OpenPGP
// Card 3.4.1, Sec. 7.5 uses its challenge as this state, rather than a message prefix.
func cmac(block cipher.Block, iv [aes.BlockSize]byte, data []byte) [aes.BlockSize]byte {
	var subkey, last [aes.BlockSize]byte

	state := iv

	defer clear(subkey[:])
	defer clear(last[:])
	defer clear(state[:])

	block.Encrypt(subkey[:], subkey[:])
	doubleCMACSubkey(&subkey)

	complete := len(data) != 0 && len(data)%aes.BlockSize == 0

	fullLength := len(data) / aes.BlockSize * aes.BlockSize

	if complete {
		fullLength -= aes.BlockSize
	} else {
		doubleCMACSubkey(&subkey)
	}

	for offset := 0; offset < fullLength; offset += aes.BlockSize {
		for i := range state {
			state[i] ^= data[offset+i]
		}

		block.Encrypt(state[:], state[:])
	}

	tail := data[fullLength:]
	copy(last[:], tail)

	if !complete {
		last[len(tail)] = 0x80
	}

	for i := range state {
		state[i] ^= last[i] ^ subkey[i]
	}

	block.Encrypt(state[:], state[:])

	return state
}

// decrypt takes authenticated, nonempty, block-aligned ciphertext and returns
// owned plaintext. Failed plaintext and removed padding are cleared.
func decrypt(block cipher.Block, iv [aes.BlockSize]byte, ciphertext []byte) ([]byte, error) {
	data := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(data, ciphertext)

	for i := len(data) - 1; i >= len(data)-aes.BlockSize; i-- {
		if data[i] == 0x80 {
			clear(data[i:])
			return data[:i], nil
		}

		if data[i] != 0 {
			break
		}
	}

	clear(data)

	return nil, fmt.Errorf("%w: invalid encrypted data padding", ErrInvalidResponse)
}

// pad returns an owned buffer with ISO/IEC 9797-1 method 2 padding.
func pad(data []byte) []byte {
	padded := make([]byte, (len(data)/aes.BlockSize+1)*aes.BlockSize)
	copy(padded, data)
	padded[len(data)] = 0x80

	return padded
}

func doubleCMACSubkey(value *[aes.BlockSize]byte) {
	carry := value[0] >> 7
	for i := range len(value) - 1 {
		value[i] = value[i]<<1 | value[i+1]>>7
	}

	value[len(value)-1] = value[len(value)-1]<<1 ^ (0x87 & (byte(0) - carry))
}
