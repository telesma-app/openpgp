package protocol_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/telesma-app/openpgp/protocol"
)

// OpenPGP Card 3.4.1, Sec. 4.3.2. The published example's outer length 5E is
// an editorial error: its listed child DOs occupy 6E bytes.
const kdfSpecContents = "8101038201088304000186a0" +
	"84083031323334353637" +
	"85081011121314151617" +
	"86084142434445464748" +
	"8720773784a602b6c81e3f092f4d7d00e17cc822d88f7360fcf2d2ef2d9d901f44b6" +
	"88202675d6164a0d4827d1d00c7eea620d015c00030a1cab38b4d0dd600b27dc9630"

func TestParseKDFSpecificationExample(t *testing.T) {
	for _, test := range []struct {
		name string
		hex  string
	}{
		{name: "children", hex: kdfSpecContents},
		{name: "template", hex: "f96e" + kdfSpecContents},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := decodeHex(t, test.hex)

			got, err := protocol.ParseKDF(data)
			if err != nil {
				t.Fatal(err)
			}

			if got.Algorithm != protocol.KDFIterSaltedS2K || got.HashAlgorithm != protocol.KDFHashSHA256 || got.IterationCount != 100000 {
				t.Errorf("algorithm/hash/count = %d/%d/%d", got.Algorithm, got.HashAlgorithm, got.IterationCount)
			}

			for _, field := range []struct {
				name string
				got  []byte
				want string
			}{
				{"PW1 salt", got.PW1Salt, "3031323334353637"},
				{"RC salt", got.ResettingCodeSalt, "1011121314151617"},
				{"PW3 salt", got.PW3Salt, "4142434445464748"},
				{"initial PW1", got.InitialPW1Hash, "773784a602b6c81e3f092f4d7d00e17cc822d88f7360fcf2d2ef2d9d901f44b6"},
				{"initial PW3", got.InitialPW3Hash, "2675d6164a0d4827d1d00c7eea620d015c00030a1cab38b4d0dd600b27dc9630"},
			} {
				if !bytes.Equal(field.got, decodeHex(t, field.want)) {
					t.Errorf("%s = %x, want %s", field.name, field.got, field.want)
				}
			}

			if !bytes.Equal(got.Raw, data) {
				t.Errorf("raw = %x, want %x", got.Raw, data)
			}
		})
	}
}

func TestEncodeKDFSpecificationExample(t *testing.T) {
	kdf := protocol.KDF{
		Algorithm: protocol.KDFIterSaltedS2K, HashAlgorithm: protocol.KDFHashSHA256,
		IterationCount: 100000,
		PW1Salt:        []byte("01234567"), ResettingCodeSalt: decodeHex(t, "1011121314151617"), PW3Salt: []byte("ABCDEFGH"),
		InitialPW1Hash: decodeHex(t, "773784a602b6c81e3f092f4d7d00e17cc822d88f7360fcf2d2ef2d9d901f44b6"),
		InitialPW3Hash: decodeHex(t, "2675d6164a0d4827d1d00c7eea620d015c00030a1cab38b4d0dd600b27dc9630"),
	}

	got := protocol.EncodeKDF(kdf)
	defer clear(got)

	if want := decodeHex(t, kdfSpecContents); !bytes.Equal(got, want) {
		t.Errorf("KDF contents = %x, want %x", got, want)
	}
}

func TestKDFNoneEncoding(t *testing.T) {
	for _, encoded := range []string{"", "f900", "810100", "81010087008803010203"} {
		t.Run(encoded, func(t *testing.T) {
			got, err := protocol.ParseKDF(decodeHex(t, encoded))
			if err != nil || got.Algorithm != protocol.KDFNone {
				t.Fatalf("KDF = %+v, %v", got, err)
			}

			want := "810100"
			if encoded == "81010087008803010203" {
				want = encoded

				if got.InitialPW1Hash == nil || len(got.InitialPW1Hash) != 0 || !bytes.Equal(got.InitialPW3Hash, []byte{1, 2, 3}) {
					t.Fatalf("NONE initial values = %x / %x", got.InitialPW1Hash, got.InitialPW3Hash)
				}
			}

			if data := protocol.EncodeKDF(got); !bytes.Equal(data, decodeHex(t, want)) {
				t.Errorf("encoded NONE = %x, want %s", data, want)
			}
		})
	}
}

func TestKDFCountAndOptionalFields(t *testing.T) {
	for _, count := range []string{"00000000", "ffffffff"} {
		data := decodeHex(t, "8101038201088304"+count+"84083031323334353637")

		got, err := protocol.ParseKDF(data)
		if err != nil {
			t.Fatal(err)
		}

		if got.ResettingCodeSalt != nil || got.PW3Salt != nil || got.InitialPW1Hash != nil || got.InitialPW3Hash != nil {
			t.Errorf("absent fields were populated: %+v", got)
		}

		if count == "00000000" && got.IterationCount != 0 || count == "ffffffff" && got.IterationCount != 0xffffffff {
			t.Errorf("count = %d, want %s", got.IterationCount, count)
		}

		if encoded := protocol.EncodeKDF(got); !bytes.Equal(encoded, data) {
			t.Errorf("count encoding = %x, want %x", encoded, data)
		}
	}
}

func TestKDFUnknownFieldsAndAlgorithms(t *testing.T) {
	for _, encoded := range []string{
		"81017f900101",
		"81010382017f83040000000084083031323334353637870101",
	} {
		data := decodeHex(t, encoded)

		got, err := protocol.ParseKDF(data)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(got.Raw, data) || got.Algorithm != 0x7f && got.HashAlgorithm != 0x7f {
			t.Errorf("unknown metadata = %+v", got)
		}
	}
}

func TestParseKDFRejectsMalformedData(t *testing.T) {
	const userSalt = "84083031323334353637"

	for name, encoded := range map[string]string{
		"truncated template":       "f901",
		"truncated child":          "8101038202",
		"trailing template data":   "f903810100810100",
		"missing algorithm":        "820108",
		"empty algorithm":          "8100",
		"long algorithm":           "81020000",
		"duplicate algorithm":      "810100810100",
		"empty hash":               "8101008200",
		"long hash":                "81010082020800",
		"short count":              "8101008303000000",
		"long count":               "81010083050000000000",
		"missing S2K hash":         "810103830400000000" + userSalt,
		"missing S2K count":        "810103820108" + userSalt,
		"missing S2K salt":         "810103820108830400000000",
		"short user salt":          "810103820108830400000000840730313233343536",
		"empty RC salt":            "810103820108830400000000" + userSalt + "8500",
		"long admin salt":          "810103820108830400000000" + userSalt + "8609414243444546474849",
		"duplicate RC salt":        "810103820108830400000000" + userSalt + "8508303132333435363785083031323334353637",
		"short SHA256 initial PW1": "810103820108830400000000" + userSalt + "870101",
		"short SHA512 initial PW3": "81010382010a830400000000" + userSalt + "880101",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := protocol.ParseKDF(decodeHex(t, encoded))
			if !errors.Is(err, protocol.ErrInvalidResponse) {
				t.Fatalf("ParseKDF = %v, want ErrInvalidResponse", err)
			}
		})
	}
}
