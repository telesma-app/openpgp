package protocol

import (
	"encoding/hex"
	"strings"
	"testing"
)

// RFC 8032, Section 7.4, Ed448's one-octet test, and RFC 7748, Section 6.2,
// Alice's X448 key pair. Card import octets follow GnuPG scd/app-openpgp.c:
// 448 secrets and public keys retain their native encoding, without a 40 prefix.
const (
	ed448Seed  = "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e"
	ed448Point = "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480"
	x448Secret = "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"
	x448Point  = "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
)

// SEC 2, Section 2.4.1: the generator is the public key for private scalar 1.
const secp256k1Generator = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"

func decodeHex(t testing.TB, value string) []byte {
	t.Helper()

	data, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func decodeMultilineHex(t testing.TB, encoded string) []byte {
	t.Helper()

	data, err := hex.DecodeString(strings.Join(strings.Fields(encoded), ""))
	if err != nil {
		t.Fatal(err)
	}

	return data
}
