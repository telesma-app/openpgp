package protocol_test

import (
	"encoding/hex"
	"strings"
	"testing"
)

func decodeHex(t testing.TB, encoded string) []byte {
	t.Helper()

	data, err := hex.DecodeString(encoded)
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
