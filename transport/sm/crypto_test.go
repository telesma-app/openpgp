package sm

import (
	"bytes"
	"crypto/aes"
	"errors"
	"testing"
)

const (
	cryptoAES128KeyHex = "2b7e151628aed2a6abf7158809cf4f3c"
	cryptoAES256KeyHex = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
	cryptoMessageHex   = "6bc1bee22e409f96e93d7e117393172a" +
		"ae2d8a571e03ac9c9eb76fac45af8e51" +
		"30c81c46a35ce411e5fbc1191a0a52ef" +
		"f69f2445df4f9b17ad2b417be66c3710"
)

func TestCBCDirectIVKnownAnswers(t *testing.T) {
	// NIST AES_CBC.pdf supplies the keys, IV and first four ciphertext blocks.
	// OpenSSL 3.5.9 enc -aes-128-cbc/-aes-256-cbc -nopad, with the IV below,
	// independently supplies all ciphertexts after explicit 80/00 padding.
	// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CBC.pdf
	iv := [aes.BlockSize]byte(decodeHex(t, "000102030405060708090a0b0c0d0e0f"))

	for _, tc := range []struct {
		name       string
		key        string
		length     int
		ciphertext string
	}{
		{name: "AES-128 empty", key: cryptoAES128KeyHex, ciphertext: "4c08220c79d9191022dc6674874ceaf8"},
		{name: "AES-128 full block", key: cryptoAES128KeyHex, length: 16, ciphertext: "7649abac8119b246cee98e9b12e9197d7bf58f5976824ae38b3866effb261160"},
		{name: "AES-128 partial block", key: cryptoAES128KeyHex, length: 20, ciphertext: "7649abac8119b246cee98e9b12e9197dd934d521a5983b7a1dc23e94e360e004"},
		{name: "AES-128 four blocks", key: cryptoAES128KeyHex, length: 64, ciphertext: "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7f434f467253f9a5969153be0552dd6ca"},
		{name: "AES-256 empty", key: cryptoAES256KeyHex, ciphertext: "3ca4c401accc469502d6eb9fbe1dc48b"},
		{name: "AES-256 full block", key: cryptoAES256KeyHex, length: 16, ciphertext: "f58c4c04d6e5f1ba779eabfb5f7bfbd6534e6cb6d8af70839993070552ad54be"},
		{name: "AES-256 partial block", key: cryptoAES256KeyHex, length: 20, ciphertext: "f58c4c04d6e5f1ba779eabfb5f7bfbd616ffa9ce6b97de8eeac96d5efe3df23a"},
		{name: "AES-256 four blocks", key: cryptoAES256KeyHex, length: 64, ciphertext: "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b92f806397e76218aa5dc403c4ca80c4b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			block, err := aes.NewCipher(decodeHex(t, tc.key))
			if err != nil {
				t.Fatal(err)
			}

			plaintext := decodeHex(t, cryptoMessageHex)[:tc.length]
			originalPlaintext := bytes.Clone(plaintext)
			ciphertext := decodeHex(t, tc.ciphertext)
			originalCiphertext := bytes.Clone(ciphertext)

			encrypted := encrypt(block, iv, plaintext)
			decrypted, err := decrypt(block, iv, ciphertext)

			if !bytes.Equal(encrypted, ciphertext) {
				t.Errorf("encrypt = %x, want %s", encrypted, tc.ciphertext)
			}

			if err != nil || !bytes.Equal(decrypted, plaintext) {
				t.Errorf("decrypt = %x, %v, want %x", decrypted, err, plaintext)
			}

			if !bytes.Equal(plaintext, originalPlaintext) || !bytes.Equal(ciphertext, originalCiphertext) {
				t.Error("CBC changed borrowed input")
			}

			if err == nil && !bytes.Equal(decrypted[len(decrypted):cap(decrypted)], make([]byte, cap(decrypted)-len(decrypted))) {
				t.Error("decrypt retained removed padding")
			}
		})
	}
}

func TestCMACKnownAnswers(t *testing.T) {
	// NIST AES_CMAC.pdf, Examples 1-4 for AES-128 and AES-256.
	// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
	for _, tc := range []struct {
		name   string
		key    string
		length int
		mac    string
	}{
		{name: "AES-128 empty", key: cryptoAES128KeyHex, mac: "bb1d6929e95937287fa37d129b756746"},
		{name: "AES-128 full block", key: cryptoAES128KeyHex, length: 16, mac: "070a16b46b4d4144f79bdd9dd04a287c"},
		{name: "AES-128 partial block", key: cryptoAES128KeyHex, length: 20, mac: "7d85449ea6ea19c823a7bf78837dfade"},
		{name: "AES-128 four blocks", key: cryptoAES128KeyHex, length: 64, mac: "51f0bebf7e3b9d92fc49741779363cfe"},
		{name: "AES-256 empty", key: cryptoAES256KeyHex, mac: "028962f61b7bf89efc6b551f4667d983"},
		{name: "AES-256 full block", key: cryptoAES256KeyHex, length: 16, mac: "28a7023f452e8f82bd4bf28d8c37c35c"},
		{name: "AES-256 partial block", key: cryptoAES256KeyHex, length: 20, mac: "156727dc0878944a023c1fe03bad6d93"},
		{name: "AES-256 four blocks", key: cryptoAES256KeyHex, length: 64, mac: "e1992190549f6ed5696a2c056c315410"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			block, err := aes.NewCipher(decodeHex(t, tc.key))
			if err != nil {
				t.Fatal(err)
			}

			message := decodeHex(t, cryptoMessageHex)[:tc.length]
			original := bytes.Clone(message)

			got := cmac(block, [aes.BlockSize]byte{}, message)

			if !bytes.Equal(got[:], decodeHex(t, tc.mac)) {
				t.Errorf("CMAC = %x, want %s", got, tc.mac)
			}

			if !bytes.Equal(message, original) {
				t.Error("CMAC changed borrowed input")
			}
		})
	}
}

func TestCMACInitialChainingValue(t *testing.T) {
	// Independent OpenSSL 3.5.9 oracle: decrypt IV with AES-ECB (-d -nopad),
	// then compute standard CMAC over that block followed by the NIST message.
	// AES_K(AES_K^-1(IV)) initializes CMAC state to IV before the message.
	// The AES-ECB decrypted IV is 2880adbdde2a0ea9dc72a7bf6201ec72 for AES-128
	// and 393e4e6cdf9b1fc836120fa2a3d8f140 for AES-256.
	iv := [aes.BlockSize]byte(decodeHex(t, "000102030405060708090a0b0c0d0e0f"))

	for _, tc := range []struct {
		name   string
		key    string
		length int
		mac    string
	}{
		{name: "AES-128 full block", key: cryptoAES128KeyHex, length: 16, mac: "532a47c598f4e024254b31e2148cf08c"},
		{name: "AES-128 partial block", key: cryptoAES128KeyHex, length: 20, mac: "8ef62b9c5da3eb8a488162ed8d9f3678"},
		{name: "AES-256 full block", key: cryptoAES256KeyHex, length: 16, mac: "5c0587afe89ea872f97d0044aff0368e"},
		{name: "AES-256 partial block", key: cryptoAES256KeyHex, length: 20, mac: "4d2b92fbcaa3efef9eb31ec2c76b44df"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			block, err := aes.NewCipher(decodeHex(t, tc.key))
			if err != nil {
				t.Fatal(err)
			}

			got := cmac(block, iv, decodeHex(t, cryptoMessageHex)[:tc.length])

			if !bytes.Equal(got[:], decodeHex(t, tc.mac)) {
				t.Errorf("CMAC with nonzero IV = %x, want %s", got, tc.mac)
			}
		})
	}
}

func TestDecryptRejectsInvalidPadding(t *testing.T) {
	// Fixed OpenSSL AES-128-CBC ciphertexts decrypt to: sixteen zero bytes,
	// fifteen zero bytes and 81, and 80 followed by thirty-one zero bytes.
	block, err := aes.NewCipher(decodeHex(t, cryptoAES128KeyHex))
	if err != nil {
		t.Fatal(err)
	}

	iv := [aes.BlockSize]byte(decodeHex(t, "000102030405060708090a0b0c0d0e0f"))

	for _, tc := range []struct {
		name       string
		ciphertext string
	}{
		{name: "zero padding", ciphertext: "50fe67cc996d32b6da0937e99bafec60"},
		{name: "wrong marker", ciphertext: "654bf2efd45da1b0f8b73e8bee87cf28"},
		{name: "padding crosses block", ciphertext: "4c08220c79d9191022dc6674874ceaf8870b35c58d3b8e753fd5d114df671c4b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext := decodeHex(t, tc.ciphertext)
			original := bytes.Clone(ciphertext)

			plaintext, err := decrypt(block, iv, ciphertext)

			if !errors.Is(err, ErrInvalidResponse) || plaintext != nil {
				t.Errorf("decrypt = %x, %v, want invalid response without plaintext", plaintext, err)
			}

			if !bytes.Equal(ciphertext, original) {
				t.Error("rejected ciphertext was modified")
			}
		})
	}
}

func TestPadISO9797Method2(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
		want string
	}{
		{name: "empty", want: "80000000000000000000000000000000"},
		{name: "one byte short", data: "000102030405060708090a0b0c0d0e", want: "000102030405060708090a0b0c0d0e80"},
		{name: "aligned", data: "000102030405060708090a0b0c0d0e0f", want: "000102030405060708090a0b0c0d0e0f80000000000000000000000000000000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := decodeHex(t, tc.data)
			original := bytes.Clone(data)

			got := pad(data)

			if !bytes.Equal(got, decodeHex(t, tc.want)) {
				t.Errorf("pad = %x, want %s", got, tc.want)
			}

			if !bytes.Equal(data, original) {
				t.Error("pad changed borrowed input")
			}
		})
	}
}
