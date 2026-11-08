package protocol_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"math/big"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/telesma-app/openpgp/protocol"
)

func TestEncodeRSAKeyImportLayouts(t *testing.T) {
	for _, tt := range []struct {
		name   string
		format protocol.ImportFormat
		prefix string
		parts  []string
	}{
		{
			name:   "standard",
			format: protocol.ImportFormatStandard,
			prefix: "4d820116b8007f480891049281809381805f48820104",
			parts:  []string{"00010001", rsaImportP, rsaImportQ},
		},
		{
			name:   "standard with modulus",
			format: protocol.ImportFormatStandardWithModulus,
			prefix: "4d82021ab8007f480c9104928180938180978201005f48820204",
			parts:  []string{"00010001", rsaImportP, rsaImportQ, rsaImportN},
		},
		{
			name:   "CRT",
			format: protocol.ImportFormatCRT,
			prefix: "4d82029fb8007f481191049281809381809481809581809681805f48820284",
			parts:  []string{"00010001", rsaImportP, rsaImportQ, rsaImportQInverse, rsaImportDP, rsaImportDQ},
		},
		{
			name:   "CRT with modulus",
			format: protocol.ImportFormatCRTWithModulus,
			prefix: "4d8203a3b8007f48159104928180938180948180958180968180978201005f48820384",
			parts:  []string{"00010001", rsaImportP, rsaImportQ, rsaImportQInverse, rsaImportDP, rsaImportDQ, rsaImportN},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key := rsaImportTestKey(t)
			before := rsaImportKeyValues(key)
			precomputed := key.Precomputed

			want := rsaImportHex(t, tt.prefix)
			for _, part := range tt.parts {
				want = append(want, rsaImportHex(t, part)...)
			}

			defer clear(want)

			got, err := protocol.EncodeKeyImport(
				protocol.ControlReferenceTemplate{Tag: protocol.ConfidentialityTemplateTag},
				protocol.AlgorithmAttributes{Algorithm: protocol.RSA, ModulusBits: 2048, ExponentBits: 32, ImportFormat: tt.format},
				key,
			)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(got)

			if !bytes.Equal(got, want) {
				t.Errorf("import payload = %x, want %x", got, want)
			}

			clear(got)

			if !slices.Equal(rsaImportKeyValues(key), before) || !reflect.DeepEqual(key.Precomputed, precomputed) {
				t.Error("encoding or clearing the payload changed the borrowed RSA key")
			}
		})
	}
}

func TestEncodeRSAKeyImportExponentWidthAndTemplate(t *testing.T) {
	for _, tt := range []struct {
		name         string
		exponentBits uint16
		template     protocol.ControlReferenceTemplate
		prefix       string
		exponent     string
	}{
		{
			name:         "three-byte exponent",
			exponentBits: 24,
			template:     protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag},
			prefix:       "4d820115b6007f480891039281809381805f48820103",
			exponent:     "010001",
		},
		{
			name:         "four-byte exponent with leading zero",
			exponentBits: 32,
			template:     protocol.ControlReferenceTemplate{Tag: protocol.DigitalSignatureTemplateTag},
			prefix:       "4d820116b6007f480891049281809381805f48820104",
			exponent:     "00010001",
		},
		{
			name:         "extended authentication template",
			exponentBits: 32,
			template:     protocol.ControlReferenceTemplate{Tag: protocol.AuthenticationTemplateTag, KeyReference: protocol.AuthenticationKeyReference},
			prefix:       "4d820119a4038401037f480891049281809381805f48820104",
			exponent:     "00010001",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key := rsaImportTestKey(t)

			want := rsaImportHex(t, tt.prefix+tt.exponent+rsaImportP+rsaImportQ)
			defer clear(want)

			got, err := protocol.EncodeKeyImport(tt.template, protocol.AlgorithmAttributes{
				Algorithm: protocol.RSA, ModulusBits: 2048, ExponentBits: tt.exponentBits,
			}, key)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(got)

			if !bytes.Equal(got, want) {
				t.Errorf("import payload = %x, want %x", got, want)
			}
		})
	}
}

func TestEncodeRSAKeyImportAttributeMismatch(t *testing.T) {
	for _, tt := range []struct {
		name       string
		attributes protocol.AlgorithmAttributes
		want       error
	}{
		{
			name:       "modulus size",
			attributes: protocol.AlgorithmAttributes{Algorithm: protocol.RSA, ModulusBits: 3072, ExponentBits: 32},
			want:       protocol.ErrKeyMismatch,
		},
		{
			name:       "exponent capacity",
			attributes: protocol.AlgorithmAttributes{Algorithm: protocol.RSA, ModulusBits: 2048, ExponentBits: 16},
			want:       protocol.ErrKeyMismatch,
		},
		{
			name:       "unsupported format",
			attributes: protocol.AlgorithmAttributes{Algorithm: protocol.RSA, ModulusBits: 2048, ExponentBits: 32, ImportFormat: 4},
			want:       protocol.ErrUnsupportedAlgorithm,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key := rsaImportTestKey(t)

			got, err := protocol.EncodeKeyImport(protocol.ControlReferenceTemplate{Tag: protocol.ConfidentialityTemplateTag}, tt.attributes, key)

			if !errors.Is(err, tt.want) || got != nil {
				t.Fatalf("import = %x, %v; want nil, %v", got, err, tt.want)
			}
		})
	}
}

func TestEncodeRSAKeyImportRejectsMultiprimeKey(t *testing.T) {
	//nolint:staticcheck // This test needs a valid multiprime RSA key to verify its rejection.
	key, err := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048)
	if err != nil {
		t.Fatal(err)
	}

	if err := key.Validate(); err != nil {
		t.Fatal(err)
	}

	got, err := protocol.EncodeKeyImport(protocol.ControlReferenceTemplate{Tag: protocol.ConfidentialityTemplateTag}, protocol.AlgorithmAttributes{
		Algorithm: protocol.RSA, ModulusBits: 2048, ExponentBits: 32,
	}, key)

	if !errors.Is(err, protocol.ErrUnsupportedAlgorithm) || got != nil {
		t.Fatalf("import = %x, %v; want nil, unsupported algorithm", got, err)
	}
}

func rsaImportTestKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: new(big.Int).SetBytes(rsaImportHex(t, rsaImportN)), E: 65537},
		D:         new(big.Int).SetBytes(rsaImportHex(t, rsaImportD)),
		Primes: []*big.Int{
			new(big.Int).SetBytes(rsaImportHex(t, rsaImportP)),
			new(big.Int).SetBytes(rsaImportHex(t, rsaImportQ)),
		},
	}
	if err := key.Validate(); err != nil {
		t.Fatal(err)
	}

	return key
}

func rsaImportKeyValues(key *rsa.PrivateKey) []string {
	return []string{key.N.Text(16), key.D.Text(16), key.Primes[0].Text(16), key.Primes[1].Text(16)}
}

func rsaImportHex(t testing.TB, encoded string) []byte {
	t.Helper()

	data, err := hex.DecodeString(strings.Join(strings.Fields(encoded), ""))
	if err != nil {
		t.Fatal(err)
	}

	return data
}

// OpenSSL RSA-2048 fixture with independently computed CRT values.
const rsaImportN = `
c97d24884afd922648095f14e31d31d883cb52ac2ac1fee9fa31a875d9d34af9
09b0cd131d3bbbbc49da91b672f7c9c96d0a1e797c9166182a3fd11016273ce1
5601e219e38425fd32d502be9389ab1f91edf96afc290c7c57acb5364981a40928
6d1750a9ee11171e49397ba2d101d8deaac5c51aacfe58bf3c6b6a2f411202ed
148b640b8afe5f16bbb1459fdfedfea6aaf4e78c264af2557c7845751a44be24
da049d07b9a2a34ad53045ae13b8c73cf14673934b83980445061f7ff0072660
c07fd6751938f706fd8534999a9dfb347beb175bd431262d3589d55a9a591e5ce1
59677c09497d3748f9c5566929eba3bba0b33cbb79c943840e3daf422285
`

const rsaImportD = `
0e6758ce397629157d7ed6023b3e220b1558da9f1e2b621abddd00eaf3d86bfa
a39bb4fd51d0ac5a08798c831b72e544f5fb8c34291887d0e06c5178b1ecba28
6daa92cc40fc786ec24c81f6b7bb56b55a0c461144d77662092e7a81d7fd6189
9a0f3a6474d164fd5f17e2f918a992553b8dbfb79871977926aa9e0f2833a1a2
dd6d27adf92a9e01f79cc98c6f2de3fcb5854b3e218cfeee649526d148bdae7e
4562af26b6c32f6acedad2369e65a06ad6353d839f32fdb00d04a0f7381fd886
1e24d4c0b4860260a4f3b47e7353f6f54e32420dbff579b82786de7137c8b88b
5a2ab1a3d261390f440471886d1d15b1779290ede7ab480f148f9c63079c613d
`

const rsaImportP = `
ea3fca6cf80f678065dd651d599d1488df4fdcd7f1ed0a89fdcfa44c5086bb9e
fffbf152817bccf0a49128eacde75ee0fc2c2c6b73d187961caec338b9d70c46
d77c134f2b64b99a4eae31aa54cb9e0ec09ab85ca1d6709db6ca3f00ceb170d0
9491d463c5632ebeab03c5e4c89506c8caa443ce75e60758c73c6e5aeb2e88f7
`

const rsaImportQ = `
dc329fae4cfd3117fa1a493fc91cb32d75805185883d44cff89f413bfea80385
fcdf238d8551710bf99da37fc7d80c48235e399f639509e2645a6dbfdd0b3ab2
956694c54ac245d7b3c1653c5bbc59d9b3abda7b3b35574fd6ea9c681f9c9bcc
e58ab53c526e9e4bf55d1b21990e9d814f71eec3697e86952bdce920591e6d63
`

const rsaImportDP = `
88ead444b1113febfa9e5755ba6567f540a18b71e5042a1ed1eda618bd10a365
a235feadbce541ba7e5622566c178a8b7299d734cf336f4ebc6121d66c395801
a83deb8360d7b4ec8e849e9ef2853953621c8d1a07b63188dda884fed1d14121
89555b911d74858408ad61e401a1a99f7f625807bb3dc2998f8ab0ee0f7cd9ad
`

const rsaImportDQ = `
d6ed12af2eb67394d3a994958dd7558ca983f60e404c8d3df18e803deef24f7e
18b4341f8e614fd6406e7d87dba82554c430d44d9f057a005fb3642c41b51435
fb5d85188d3fd2ac17e84cc7fd427af0e34e7a928dd822c0eb255444cd962efc
6f905415ecdfcbe2983ba89fc2a5615736141ed8ddbf81dd5852e7b98b4307c1
`

const rsaImportQInverse = `
069fa70f6606a0e4cddfaaffaa7bff2c1b94fada96ae19e92a384fedca75ca55
a57e7bf15aad17fba51a7e2c3e93ba10db7d55dc6795b880de6bbd0fa781ab5f
4e4e4645051a5d0fb433f917bdd3b67785472e3f9668745d683f9e31a8a3b524
178289ed113bcca49761a6ce4e64e40f77f0b28256f45ff558c922cb77093fcb
`
