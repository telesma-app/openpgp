package sm

import (
	"bytes"
	"errors"
	"testing"

	"github.com/telesma-app/iso7816"
)

func TestRecordKnownAnswers(t *testing.T) {
	// OpenPGP Card 3.4.1, Sec. 7.5, pp. 82-86. Independently calculated with
	// OpenSSL 3.5.9 enc -aes-128-cbc/-aes-256-cbc -nopad and dgst -mac cmac.
	// ENC is 00..0f or 00..1f, MAC is 20..2f or 20..3f, and RND is 00..0f.
	// CBC uses RND directly after explicit 80/00 padding. To obtain CMAC with
	// initial state RND, standard OpenSSL CMAC receives AES_K^-1(RND) followed
	// by the already padded record input. Header-only commands have exactly
	// one padded header block; there is no second, empty-body padding block.
	rnd := [16]byte(decodeHex(t, "000102030405060708090a0b0c0d0e0f"))

	for _, tc := range []struct {
		name      string
		keySize   int
		encoding  iso7816.Encoding
		macLength int
		command   iso7816.Command
		protected string
		response  string
		plaintext string
		status    iso7816.StatusWord
	}{
		{
			name: "AES128 even read", keySize: 16, encoding: iso7816.EncodingShort, macLength: 8,
			command:   iso7816.Command{INS: 0xca, P2: 0xc4, Le: 256, Encoding: iso7816.EncodingShort},
			protected: "0cca00c40d9701008e08761630cdf44a1e8f00",
			response:  "871101b35767e38f25c145c70fdae194095f64990290008e08284f46b6823e6f9e9000",
			plaintext: "010203040506", status: 0x9000,
		},
		{
			name: "AES128 odd read", keySize: 16, encoding: iso7816.EncodingShort, macLength: 8,
			command:   iso7816.Command{INS: 0x47, P1: 0x81, Data: []byte{0xb6, 0}, Le: 256, Encoding: iso7816.EncodingShort},
			protected: "0c4781001f8510d0da67b96e0596f5b869795144f11d5e9701008e08b95e35dbf39e19a000",
			response:  "851017157ca95f7b1336a2fa23d1d1125e56990290008e08f45c3dd8f0f5cce69000",
			plaintext: "7f4903860104", status: 0x9000,
		},
		{
			name: "AES256 full MAC extended maximum Le", keySize: 32, encoding: iso7816.EncodingExtended, macLength: 16,
			command:   iso7816.Command{INS: 0xca, P2: 0xc4, Le: 65536, Encoding: iso7816.EncodingExtended},
			protected: "0cca00c4000016970200008e10ee9f0c92be2be334bc4d3b767bb5ea160000",
			response:  "99026a888e108c10b31837e4b2db6b4ba8b3615967fc6a88",
			status:    0x6a88,
		},
		{
			name: "logical extended Le over short framing", keySize: 16, encoding: iso7816.EncodingShort, macLength: 8,
			command:   iso7816.Command{INS: 0xca, P2: 0xc4, Le: 256, Encoding: iso7816.EncodingExtended},
			protected: "0cca00c40e970201008e08a0a1c37e8272e23c00",
			response:  "8711011a06c4c6c202781b82d0adbe44141712990290008e08a0c18efea94bfb1d9000",
			plaintext: "10203040", status: 0x9000,
		},
		{
			name: "logical short Le over extended framing", keySize: 32, encoding: iso7816.EncodingExtended, macLength: 16,
			command:   iso7816.Command{INS: 0xca, P2: 0xc4, Le: 256, Encoding: iso7816.EncodingShort},
			protected: "0cca00c40000159701008e10d585c6da7297d78621e79d22a0c2a04c0000",
			response:  "871101d4e23ccf2443f55530f2e02ec0d0dff3990290008e10a5bd51bca56db75cc0b04ba55b9e84a49000",
			plaintext: "01020304", status: 0x9000,
		},
		{
			name: "AES256 even change reference without Le", keySize: 32, encoding: iso7816.EncodingExtended, macLength: 16,
			command:   iso7816.Command{INS: 0x24, P2: 0x83, Data: decodeHex(t, "31323334353637383132333435363738"), Encoding: iso7816.EncodingShort},
			protected: "0c2400830000358721019eb2c797b7e60975df26b1258a8a64a795d6b1c9fce5ac412c28666c74a9b1e38e10ebd2537777be7f0e7e73d4a84161edee0000",
			response:  "9000", status: 0x9000,
		},
		{
			name: "AES128 odd write without Le", keySize: 16, encoding: iso7816.EncodingShort, macLength: 8,
			command:   iso7816.Command{INS: 0xdb, P1: 0x3f, P2: 0xff, Data: []byte{0x4d, 0}, Encoding: iso7816.EncodingShort},
			protected: "0cdb3fff1c8510bcd6bfde701adb7c8b9760d95d7bc6c28e08a5afa6d7763d059700",
			response:  "9000", status: 0x9000,
		},
		{
			name: "AES256 header only", keySize: 32, encoding: iso7816.EncodingShort, macLength: 16,
			command:   iso7816.Command{INS: 0x20, P2: 0x83, Encoding: iso7816.EncodingShort},
			protected: "0c200083128e105ad96636be2b564733a683b95ad5153900",
			response:  "63c3", status: 0x63c3,
		},
		{
			name: "automatic extended logical Le", keySize: 16, encoding: iso7816.EncodingExtended, macLength: 8,
			command:   iso7816.Command{INS: 0xca, P2: 0xc4, Le: 512, Encoding: iso7816.EncodingAuto},
			protected: "0cca00c400000e970202008e0890efb76b71c841940000",
			response:  "8711014d6228baf25aabfb0a4221c0e31673fb990290008e08c2afbead12c8535f9000",
			plaintext: "aabbccdd", status: 0x9000,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, err := newRecordSession(recordKeys(tc.keySize), tc.encoding, tc.macLength)
			if err != nil {
				t.Fatal(err)
			}

			t.Cleanup(session.clear)

			originalData := bytes.Clone(tc.command.Data)

			if err := session.validateCommand(tc.command); err != nil {
				t.Fatal(err)
			}

			protected := session.protect(tc.command, rnd)

			wire, err := protected.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(wire, decodeHex(t, tc.protected)) {
				t.Errorf("protected APDU = %x, want %s", wire, tc.protected)
			}

			if !bytes.Equal(tc.command.Data, originalData) {
				t.Error("protect changed borrowed command data")
			}

			response, err := iso7816.ParseResponse(decodeHex(t, tc.response))
			if err != nil {
				t.Fatal(err)
			}

			originalResponse := bytes.Clone(response.Data)

			plaintext, err := session.unprotect(tc.command, response, rnd)
			if err != nil {
				t.Fatal(err)
			}

			if plaintext.Status != tc.status || !bytes.Equal(plaintext.Data, decodeHex(t, tc.plaintext)) {
				t.Errorf("unprotect = data %x status %s, want %s status %s", plaintext.Data, plaintext.Status, tc.plaintext, tc.status)
			}

			if !bytes.Equal(response.Data, originalResponse) {
				t.Error("unprotect changed borrowed response data")
			}
		})
	}
}

func TestRecordRejectsUnauthenticatedAndMalformedResponses(t *testing.T) {
	// The valid-MAC padding and wrong-tag records were independently produced
	// with the OpenSSL oracle documented by TestRecordKnownAnswers.
	rnd := [16]byte(decodeHex(t, "000102030405060708090a0b0c0d0e0f"))

	for _, tc := range []struct {
		name           string
		response       string
		oddInstruction bool
		wrongChallenge bool
		authentication bool
	}{
		{name: "wrong MAC", response: "871101b35767e38f25c145c70fdae194095f64990290008e08284f46b6823e6f9f9000", authentication: true},
		{name: "wrong challenge", response: "871101b35767e38f25c145c70fdae194095f64990290008e08284f46b6823e6f9e9000", wrongChallenge: true, authentication: true},
		{name: "authenticated invalid padding", response: "8711010a940bb5416ef045f1c39458c653ea5a990290008e0878a453324fd903899000"},
		{name: "outer status differs", response: "871101b35767e38f25c145c70fdae194095f64990290008e08284f46b6823e6f9e6a88"},
		{name: "even instruction odd response tag", response: "8510e9c1e7cce943de079d70697443acbd39990290008e0828d697d6ad1fb01b9000"},
		{name: "odd instruction even response tag", response: "871101e9c1e7cce943de079d70697443acbd39990290008e085e723f2531772b2b9000", oddInstruction: true},
		{name: "bare status with expected response", response: "9000"},
		{name: "missing MAC", response: "990290009000"},
		{name: "MAC before status", response: "8e080000000000000000990290009000"},
		{name: "duplicate status", response: "99029000990290008e0800000000000000009000"},
		{name: "short MAC", response: "990290008e07000000000000009000"},
		{name: "trailing object", response: "990290008e080000000000000000990290009000"},
		{name: "partial ciphertext block", response: "87020100990290008e0800000000000000009000"},
		{name: "truncated object", response: "879000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, err := newRecordSession(recordKeys(16), iso7816.EncodingShort, 8)
			if err != nil {
				t.Fatal(err)
			}

			t.Cleanup(session.clear)

			command := iso7816.Command{INS: 0xca, P2: 0xc4, Le: 256, Encoding: iso7816.EncodingShort}
			if tc.oddInstruction {
				command = iso7816.Command{INS: 0x47, P1: 0x81, Data: []byte{0xb6, 0}, Le: 256, Encoding: iso7816.EncodingShort}
			}

			challenge := rnd
			if tc.wrongChallenge {
				challenge[0] ^= 1
			}

			response, err := iso7816.ParseResponse(decodeHex(t, tc.response))
			if err != nil {
				t.Fatal(err)
			}

			original := bytes.Clone(response.Data)

			plaintext, err := session.unprotect(command, response, challenge)

			if !errors.Is(err, ErrInvalidResponse) || errors.Is(err, ErrAuthentication) != tc.authentication {
				t.Errorf("unprotect = %v, want invalid response with authentication failure %t", err, tc.authentication)
			}

			if plaintext.Data != nil || plaintext.Status != 0 {
				t.Errorf("rejected response released data %x or status %s", plaintext.Data, plaintext.Status)
			}

			if !bytes.Equal(response.Data, original) {
				t.Error("rejection changed borrowed response data")
			}
		})
	}
}

func TestRecordRejectsDataForStatusOnlyCommand(t *testing.T) {
	session, err := newRecordSession(recordKeys(16), iso7816.EncodingShort, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer session.clear()

	command := iso7816.Command{INS: 0x20, P2: 0x83, Encoding: iso7816.EncodingShort}
	rnd := [16]byte(decodeHex(t, "000102030405060708090a0b0c0d0e0f"))

	response, err := iso7816.ParseResponse(decodeHex(t, "871101b35767e38f25c145c70fdae194095f64990290008e08284f46b6823e6f9e9000"))
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := session.unprotect(command, response, rnd)

	if !errors.Is(err, ErrInvalidResponse) || plaintext.Data != nil || plaintext.Status != 0 {
		t.Errorf("unprotect = %+v, %v, want invalid response without data or status", plaintext, err)
	}
}
