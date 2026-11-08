package protocol

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"slices"
	"testing"
)

func TestEncodeNISTKeyImport(t *testing.T) {
	for _, curve := range []struct {
		name          string
		ecdsa         elliptic.Curve
		ecdh          ecdh.Curve
		oid           []byte
		width         int
		privatePrefix string
		publicPrefix  string
	}{
		{
			name: "P256", ecdsa: elliptic.P256(), ecdh: ecdh.P256(), width: 32,
			oid:           []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
			privatePrefix: "4d2ab6007f480292205f4820",
			publicPrefix:  "4d6db6007f4804922099415f4861",
		},
		{
			name: "P384", ecdsa: elliptic.P384(), ecdh: ecdh.P384(), width: 48,
			oid:           []byte{0x2b, 0x81, 0x04, 0x00, 0x22},
			privatePrefix: "4d3ab6007f480292305f4830",
			publicPrefix:  "4d819eb6007f4804923099615f488191",
		},
		{
			name: "P521", ecdsa: elliptic.P521(), ecdh: ecdh.P521(), width: 66,
			oid:           []byte{0x2b, 0x81, 0x04, 0x00, 0x23},
			privatePrefix: "4d4cb6007f480292425f4842",
			publicPrefix:  "4d81d5b6007f480592429981855f4881c7",
		},
	} {
		t.Run(curve.name, func(t *testing.T) {
			// Scalar one requires leading zero padding and has the independent
			// SEC 2 generator as its public point on each curve.
			scalar := make([]byte, curve.width)
			scalar[len(scalar)-1] = 1
			point := make([]byte, 1+2*curve.width)
			point[0] = 4
			curve.ecdsa.Params().Gx.FillBytes(point[1 : 1+curve.width])
			curve.ecdsa.Params().Gy.FillBytes(point[1+curve.width:])

			for _, family := range []struct {
				name      string
				algorithm Algorithm
			}{
				{name: "ECDSA", algorithm: ECDSA},
				{name: "ECDH", algorithm: ECDH},
			} {
				t.Run(family.name, func(t *testing.T) {
					var (
						key crypto.PrivateKey
						err error
					)
					if family.algorithm == ECDSA {
						key, err = ecdsa.ParseRawPrivateKey(curve.ecdsa, scalar)
					} else {
						key, err = curve.ecdh.NewPrivateKey(scalar)
					}

					if err != nil {
						t.Fatal(err)
					}

					for _, format := range []struct {
						name   string
						value  ImportFormat
						prefix string
					}{
						{name: "private only", prefix: curve.privatePrefix},
						{name: "with public point", value: ImportFormatStandardWithPublicKey, prefix: curve.publicPrefix},
					} {
						t.Run(format.name, func(t *testing.T) {
							prefix, err := hex.DecodeString(format.prefix)
							if err != nil {
								t.Fatal(err)
							}

							want := slices.Concat(prefix, scalar)
							if format.value == ImportFormatStandardWithPublicKey {
								want = append(want, point...)
							}

							got, err := EncodeKeyImport(ControlReferenceTemplate{Tag: DigitalSignatureTemplateTag}, AlgorithmAttributes{
								Algorithm: family.algorithm, CurveOID: curve.oid, ImportFormat: format.value,
							}, key)
							if err != nil {
								t.Fatal(err)
							}

							if !bytes.Equal(got, want) {
								t.Errorf("key import = %x, want %x", got, want)
							}

							raw, err := EncodeKeyImport(ControlReferenceTemplate{Tag: DigitalSignatureTemplateTag}, AlgorithmAttributes{
								Algorithm: family.algorithm, CurveOID: curve.oid, ImportFormat: format.value,
							}, ECPrivateKey{CurveOID: curve.oid, Scalar: scalar, PublicPoint: point})
							if err != nil {
								t.Fatal(err)
							}

							if !bytes.Equal(raw, want) {
								t.Errorf("protocol key import = %x, want %x", raw, want)
							}

							clear(got)
							clear(raw)

							private, public := ecImportKeyBytes(t, key)
							defer clear(private)

							if !bytes.Equal(private, scalar) || !bytes.Equal(public, point) {
								t.Error("encoding or clearing the result changed the borrowed key")
							}
						})
					}
				})
			}
		})
	}
}

func TestNISTKeyImportAttributeMismatch(t *testing.T) {
	scalar := [32]byte{31: 1}

	ecdsaKey, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar[:])
	if err != nil {
		t.Fatal(err)
	}

	ecdhKey, err := ecdh.P256().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatal(err)
	}

	x25519, err := ecdh.X25519().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatal(err)
	}

	p256 := []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

	p384 := []byte{0x2b, 0x81, 0x04, 0x00, 0x22}
	for _, test := range []struct {
		name       string
		attributes AlgorithmAttributes
		key        crypto.PrivateKey
	}{
		{name: "ECDSA curve", attributes: AlgorithmAttributes{Algorithm: ECDSA, CurveOID: p384}, key: ecdsaKey},
		{name: "ECDH curve", attributes: AlgorithmAttributes{Algorithm: ECDH, CurveOID: p384}, key: ecdhKey},
		{name: "ECDSA attributes with ECDH key", attributes: AlgorithmAttributes{Algorithm: ECDSA, CurveOID: p256}, key: ecdhKey},
		{name: "ECDH attributes with ECDSA key", attributes: AlgorithmAttributes{Algorithm: ECDH, CurveOID: p256}, key: ecdsaKey},
		{name: "X25519 attributes with NIST key", attributes: AlgorithmAttributes{Algorithm: ECDH, CurveOID: []byte{0x2b, 0x65, 0x6e}}, key: ecdhKey},
		{name: "NIST attributes with X25519 key", attributes: AlgorithmAttributes{Algorithm: ECDH, CurveOID: p256}, key: x25519},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := EncodeKeyImport(ControlReferenceTemplate{Tag: DigitalSignatureTemplateTag}, test.attributes, test.key)
			if got != nil || !errors.Is(err, ErrKeyMismatch) {
				t.Fatalf("EncodeKeyImport = %x, %v; want nil and key mismatch", got, err)
			}
		})
	}
}

func TestNISTKeyImportUnsupportedAttributes(t *testing.T) {
	scalar := [32]byte{31: 1}

	ecdsaKey, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar[:])
	if err != nil {
		t.Fatal(err)
	}

	ecdhKey, err := ecdh.P256().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatal(err)
	}

	p256 := []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	for _, test := range []struct {
		name       string
		attributes AlgorithmAttributes
		key        crypto.PrivateKey
	}{
		{name: "ECDSA import format", attributes: AlgorithmAttributes{Algorithm: ECDSA, CurveOID: p256, ImportFormat: 1}, key: ecdsaKey},
		{name: "ECDH import format", attributes: AlgorithmAttributes{Algorithm: ECDH, CurveOID: p256, ImportFormat: 1}, key: ecdhKey},
		{
			name:       "ECDSA unknown curve",
			attributes: AlgorithmAttributes{Algorithm: ECDSA, CurveOID: []byte{0x2b, 0x81, 0x04, 0x00, 0x09}},
			key:        ecdsaKey,
		},
		{
			name:       "ECDH unknown curve",
			attributes: AlgorithmAttributes{Algorithm: ECDH, CurveOID: []byte{0x2b, 0x81, 0x04, 0x00, 0x09}},
			key:        ecdhKey,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := EncodeKeyImport(ControlReferenceTemplate{Tag: DigitalSignatureTemplateTag}, test.attributes, test.key)
			if got != nil || !errors.Is(err, ErrUnsupportedAlgorithm) {
				t.Fatalf("EncodeKeyImport = %x, %v; want nil and unsupported algorithm", got, err)
			}
		})
	}
}

func TestEncodeX25519KeyImportRFC7748(t *testing.T) {
	// RFC 7748, Sec. 6.1, Alice's private key and public key. The expected
	// OpenPGP private encoding below is independently written in big-endian order.
	const privateHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"

	const importPrivateHex = "2a2cb91da5fb77b12a99c0eb872f4cdf4566b25172c1163c7da518730a6d0777"

	const publicHex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"

	private := curve25519ImportHex(t, privateHex)
	defer clear(private)

	public := curve25519ImportHex(t, publicHex)

	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(key.PublicKey().Bytes(), public) {
		t.Fatal("RFC 7748 fixture does not match Alice's public key")
	}

	for _, oid := range []struct {
		name  string
		value []byte
	}{
		{name: "legacy", value: []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}},
		{name: "RFC 8410", value: []byte{0x2b, 0x65, 0x6e}},
	} {
		t.Run(oid.name, func(t *testing.T) {
			for _, format := range []struct {
				name  string
				value ImportFormat
				wire  string
			}{
				{name: "private only", wire: "4d2ab8007f480292205f4820" + importPrivateHex},
				{
					name: "with public point", value: ImportFormatStandardWithPublicKey,
					wire: "4d4db8007f4804922099215f4841" + importPrivateHex + "40" + publicHex,
				},
			} {
				t.Run(format.name, func(t *testing.T) {
					want := curve25519ImportHex(t, format.wire)
					defer clear(want)

					got, err := EncodeKeyImport(ControlReferenceTemplate{Tag: ConfidentialityTemplateTag}, AlgorithmAttributes{
						Algorithm: ECDH, CurveOID: oid.value, ImportFormat: format.value,
					}, key)
					if err != nil {
						t.Fatal(err)
					}

					if !bytes.Equal(got, want) {
						t.Errorf("X25519 key import = %x, want %x", got, want)
					}

					clear(got)

					hostPrivate := key.Bytes()
					defer clear(hostPrivate)

					if !bytes.Equal(hostPrivate, private) || !bytes.Equal(key.PublicKey().Bytes(), public) {
						t.Error("encoding or clearing the output changed the borrowed X25519 key")
					}
				})
			}
		})
	}
}

func ecImportKeyBytes(t testing.TB, key crypto.PrivateKey) ([]byte, []byte) {
	t.Helper()

	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		private, err := key.Bytes()
		if err != nil {
			t.Fatal(err)
		}

		public, err := key.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}

		return private, public
	case *ecdh.PrivateKey:
		return key.Bytes(), key.PublicKey().Bytes()
	default:
		t.Fatalf("unsupported fixture key type %T", key)
		return nil, nil
	}
}
