package protocol_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/telesma-app/openpgp/protocol"
)

// The SHA-256 user/admin vectors are from OpenPGP Card 3.4.1, Sec. 4.3.2:
// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf
// Other vectors independently hash the expanded salt || password stream with
// Python hashlib and OpenSSL 3.5.9. RFC 4880, Sec. 3.7.1.3 defines the byte
// count and complete-first-pattern rule, rather than repeated digest rounds:
// https://www.rfc-editor.org/rfc/rfc4880#section-3.7.1.3
func TestKDFDeriveKnownAnswers(t *testing.T) {
	for _, tt := range []struct {
		name     string
		hash     protocol.KDFHashAlgorithm
		salt     string
		password string
		count    uint32
		admin    bool
		want     string
	}{
		{
			name: "specification user SHA256", hash: protocol.KDFHashSHA256,
			salt: "3031323334353637", password: "313233343536", count: 100000,
			want: "773784a602b6c81e3f092f4d7d00e17cc822d88f7360fcf2d2ef2d9d901f44b6",
		},
		{
			name: "specification admin SHA256", hash: protocol.KDFHashSHA256,
			salt: "4142434445464748", password: "3132333435363738", count: 100000, admin: true,
			want: "2675d6164a0d4827d1d00c7eea620d015c00030a1cab38b4d0dd600b27dc9630",
		},
		{
			name: "user SHA512", hash: protocol.KDFHashSHA512,
			salt: "3031323334353637", password: "313233343536", count: 100000,
			want: "9cb102d4452e431f9338c837ac67d713794d3ca93b03d53f9e08216a83b61ec6c" +
				"0fcae8f416cb8ad7d180a46dab0c48e7e6a5f2a533d62555fd66f99f0dce34f",
		},
		{
			name: "admin SHA512", hash: protocol.KDFHashSHA512,
			salt: "4142434445464748", password: "3132333435363738", count: 100000, admin: true,
			want: "fc895cf20d5e8375f78f64e589f7dabb877d3aca9c91bb20fd0732306dc90d2f" +
				"fa6bbf34d810a9a97219778d93458fa1b7fb2438b11105ae60b9768049dcbcde",
		},
		{
			name: "UTF8 SHA256", hash: protocol.KDFHashSHA256,
			salt: "0001020304050607", password: "d0bfd0b0d180d0bed0bbd18c", count: 1025,
			want: "8ddc130bd417910dd0f1c353319bb40d9a651d44f0ad6470a3d7674c6acc044c",
		},
		{
			name: "UTF8 SHA512", hash: protocol.KDFHashSHA512,
			salt: "0001020304050607", password: "d0bfd0b0d180d0bed0bbd18c", count: 1025,
			want: "cb85c536865cc19b22a7a32625454c600be62848d2e57b88be73596d61c87cbeb" +
				"3bdd70ae746972efa59f50d5c36f7e6b8158f25a741a3949c1eff715fdb86ab",
		},
		{
			name: "binary password SHA256", hash: protocol.KDFHashSHA256,
			salt: "0001020304050607", password: "00ff80000102", count: 31,
			want: "5cf218f290c42a67cc1d9e8b6e715c2943deeacdef375ecdda089fe3f56a2336",
		},
		{
			name: "binary password SHA512", hash: protocol.KDFHashSHA512,
			salt: "0001020304050607", password: "00ff80000102", count: 31,
			want: "6a13e3e8d996eb0cc20ac675fef7e1e655b45ce531cbe070553de2583b2fae6c" +
				"c1c639e460cb1b6eb44f40fac9b95bd6ce778d9d8f877ea1888b2594eb335e45",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			salt := kdfDeriveHex(t, tt.salt)
			password := kdfDeriveHex(t, tt.password)
			kdf := protocol.KDF{
				Algorithm: protocol.KDFIterSaltedS2K, HashAlgorithm: tt.hash,
				IterationCount: tt.count, PW1Salt: salt,
			}

			derive := kdf.DerivePW1
			if tt.admin {
				kdf.PW3Salt = salt
				derive = kdf.DerivePW3
			}

			got, err := derive(password)
			if err != nil {
				t.Fatal(err)
			}

			if hex.EncodeToString(got) != tt.want {
				t.Errorf("derived password = %x, want %s", got, tt.want)
			}

			clear(got)

			if hex.EncodeToString(password) != tt.password || hex.EncodeToString(salt) != tt.salt {
				t.Error("deriving or clearing the result changed borrowed password or salt")
			}
		})
	}
}

func TestKDFDeriveByteCount(t *testing.T) {
	const (
		minimumSHA256 = "e4b90d63237d4e6f88e6e894d473b8763673ba0b23d6e4760fb1fe0d719bddbc"
		minimumSHA512 = "1e07fd3e146cb613c677282beb0c3b65a39601c8e5a2dfdf1942f03832dcbb6ce" +
			"fe11790fec4d99718c2d5e0b39356812395b8bbd02536420e4a5324cf727c82"
	)
	for _, tt := range []struct {
		count  uint32
		sha256 string
		sha512 string
	}{
		{count: 0, sha256: minimumSHA256, sha512: minimumSHA512},
		{count: 13, sha256: minimumSHA256, sha512: minimumSHA512},
		{count: 14, sha256: minimumSHA256, sha512: minimumSHA512},
		{
			count:  15,
			sha256: "b11950ecf288d5e32ec1a94ba9d7c8c9113fc28184c9db3f02a0fba47daf7c4b",
			sha512: "06099160358186b4b619b15471bbbabe952dea201172359b3c397b811b201abf0c" +
				"ad514dc9c6eb258fd54e3f8a9a8bd3576e5a1d67e1f2ad3dde4d90721d5898",
		},
		{
			count:  29,
			sha256: "3ddcde6f598faa9d5b87e5bc6516d9a1f2618f34ec493e2ee9793c13812ab3c6",
			sha512: "a124eeb496c2c36dcb3f26892eff8157acb3170833852edf5d05c9f7e037fd739" +
				"8e821a8b5b1da06ff4b45fbf4660a342e7b43144d37dc049d05e3efca32087c",
		},
	} {
		for _, hash := range []struct {
			algorithm protocol.KDFHashAlgorithm
			want      string
		}{
			{algorithm: protocol.KDFHashSHA256, want: tt.sha256},
			{algorithm: protocol.KDFHashSHA512, want: tt.sha512},
		} {
			t.Run(fmt.Sprintf("count%d/hash%d", tt.count, hash.algorithm), func(t *testing.T) {
				kdf := protocol.KDF{
					Algorithm: protocol.KDFIterSaltedS2K, HashAlgorithm: hash.algorithm,
					IterationCount: tt.count, PW1Salt: []byte("01234567"),
				}

				got, err := kdf.DerivePW1([]byte("123456"))
				if err != nil {
					t.Fatal(err)
				}

				if hex.EncodeToString(got) != hash.want {
					t.Errorf("derived password = %x, want %s", got, hash.want)
				}
			})
		}
	}
}

func TestKDFDeriveSelectsPasswordSalt(t *testing.T) {
	for _, separateSalts := range []bool{false, true} {
		t.Run(fmt.Sprintf("separate salts=%t", separateSalts), func(t *testing.T) {
			kdf := protocol.KDF{
				Algorithm: protocol.KDFIterSaltedS2K, HashAlgorithm: protocol.KDFHashSHA256,
				IterationCount: 100000, PW1Salt: []byte("01234567"),
				InitialPW1Hash: bytes.Repeat([]byte{0xa5}, 32),
				InitialPW3Hash: bytes.Repeat([]byte{0x5a}, 32),
			}
			wantPW3 := "fb156e263de1eb1ea0feccf31c707dd328f7165d819b427a769b0cc6230505a5"
			wantRC := "fb156e263de1eb1ea0feccf31c707dd328f7165d819b427a769b0cc6230505a5"

			if separateSalts {
				kdf.PW3Salt = []byte("ABCDEFGH")
				kdf.ResettingCodeSalt = []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}
				wantPW3 = "2675d6164a0d4827d1d00c7eea620d015c00030a1cab38b4d0dd600b27dc9630"
				wantRC = "23bf6272118e8b0ee4cc9732821463121849ee05490727f5d554d9abf15a0700"
			}

			for _, tt := range []struct {
				name     string
				derive   func([]byte) ([]byte, error)
				password string
				want     string
			}{
				{name: "PW1", derive: kdf.DerivePW1, password: "123456", want: "773784a602b6c81e3f092f4d7d00e17cc822d88f7360fcf2d2ef2d9d901f44b6"},
				{name: "PW3", derive: kdf.DerivePW3, password: "12345678", want: wantPW3},
				{name: "resetting code", derive: kdf.DeriveResettingCode, password: "12345678", want: wantRC},
			} {
				t.Run(tt.name, func(t *testing.T) {
					got, err := tt.derive([]byte(tt.password))
					if err != nil {
						t.Fatal(err)
					}

					if hex.EncodeToString(got) != tt.want {
						t.Errorf("derived password = %x, want %s", got, tt.want)
					}

					clear(got)
				})
			}

			if !bytes.Equal(kdf.InitialPW1Hash, bytes.Repeat([]byte{0xa5}, 32)) ||
				!bytes.Equal(kdf.InitialPW3Hash, bytes.Repeat([]byte{0x5a}, 32)) {
				t.Error("deriving or clearing a result changed initial password hashes")
			}
		})
	}
}

func TestKDFNoneReturnsOwnedPassword(t *testing.T) {
	kdf := protocol.KDF{Algorithm: protocol.KDFNone}
	for _, tt := range []struct {
		name   string
		derive func([]byte) ([]byte, error)
	}{
		{name: "PW1", derive: kdf.DerivePW1},
		{name: "PW3", derive: kdf.DerivePW3},
		{name: "resetting code", derive: kdf.DeriveResettingCode},
	} {
		t.Run(tt.name, func(t *testing.T) {
			password := []byte("12345678")

			got, err := tt.derive(password)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got, password) {
				t.Errorf("NONE password = %x, want %x", got, password)
			}

			clear(got)

			if string(password) != "12345678" {
				t.Error("clearing the owned NONE result changed the borrowed password")
			}
		})
	}
}

func TestKDFDeriveUsesCurrentPassword(t *testing.T) {
	kdf := protocol.KDF{
		Algorithm: protocol.KDFIterSaltedS2K, HashAlgorithm: protocol.KDFHashSHA256,
		IterationCount: 100000, PW1Salt: []byte("01234567"),
	}
	password := []byte("123456")

	first, err := kdf.DerivePW1(password)
	if err != nil {
		t.Fatal(err)
	}

	copy(password, "654321")

	second, err := kdf.DerivePW1(password)
	if err != nil {
		t.Fatal(err)
	}

	clear(first)

	const want = "1d77f68c5b95929812aae9c6530bb3b50f5f6717916f50ccbbe5f4991ffe10c2"
	if hex.EncodeToString(second) != want {
		t.Errorf("derived changed password = %x, want %s", second, want)
	}

	if string(password) != "654321" {
		t.Error("deriving changed the borrowed password")
	}
}

func TestKDFDeriveRejectsUnsupportedAlgorithms(t *testing.T) {
	for _, tt := range []struct {
		name      string
		algorithm byte
		hash      byte
	}{
		{name: "unknown KDF", algorithm: 0x7f, hash: byte(protocol.KDFHashSHA256)},
		{name: "unknown hash", algorithm: byte(protocol.KDFIterSaltedS2K), hash: 0x7f},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte{
				0x81, 1, tt.algorithm, 0x82, 1, tt.hash,
				0x83, 4, 0, 1, 0x86, 0xa0,
				0x84, 8, '0', '1', '2', '3', '4', '5', '6', '7',
			}

			kdf, err := protocol.ParseKDF(data)
			if err != nil {
				t.Fatal(err)
			}

			for _, derive := range []func([]byte) ([]byte, error){kdf.DerivePW1, kdf.DerivePW3, kdf.DeriveResettingCode} {
				got, err := derive([]byte("12345678"))
				if !errors.Is(err, protocol.ErrUnsupportedAlgorithm) || got != nil {
					t.Errorf("unsupported derivation = %x, %v", got, err)
				}
			}
		})
	}
}

func kdfDeriveHex(t testing.TB, encoded string) []byte {
	t.Helper()

	data, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}

	return data
}
