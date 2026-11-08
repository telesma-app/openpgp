package client_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/hex"
	"testing"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

func TestBrainpoolReadAndGenerate(t *testing.T) {
	// Fixed generators from RFC 5639, Sections 3.4, 3.6 and 3.7, also listed
	// in the OpenPGP Card 3.4.1 annex. No host curve implementation produces
	// these response fixtures.
	for _, curve := range []struct {
		name  string
		oid   []byte
		point string
	}{
		{
			name: "brainpoolP256r1", oid: []byte{0x2b, 0x24, 3, 3, 2, 8, 1, 1, 7},
			point: "04" +
				"8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262" +
				"547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
		},
		{
			name: "brainpoolP384r1", oid: []byte{0x2b, 0x24, 3, 3, 2, 8, 1, 1, 0x0b},
			point: "04" +
				"1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e" +
				"8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315",
		},
		{
			name: "brainpoolP512r1", oid: []byte{0x2b, 0x24, 3, 3, 2, 8, 1, 1, 0x0d},
			point: "04" +
				"81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822" +
				"7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
		},
	} {
		t.Run(curve.name, func(t *testing.T) {
			point, err := hex.DecodeString(curve.point)
			if err != nil {
				t.Fatal(err)
			}

			for _, algorithm := range []struct {
				name       string
				algorithm  protocol.Algorithm
				tag        protocol.ControlReferenceTemplateTag
				attributes byte
			}{
				{name: "ECDSA", algorithm: protocol.ECDSA, tag: protocol.DigitalSignatureTemplateTag, attributes: 0xc1},
				{name: "ECDH", algorithm: protocol.ECDH, tag: protocol.ConfidentialityTemplateTag, attributes: 0xc2},
			} {
				t.Run(algorithm.name, func(t *testing.T) {
					attributes := append([]byte{byte(algorithm.algorithm)}, curve.oid...)
					application := bertlv.Append(nil, 0x4f, []byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 1, 0, 0, 0, 1, 0, 0})
					application = bertlv.Append(application, 0x73, bertlv.Append(nil, uint32(algorithm.attributes), attributes))
					application = bertlv.Append(nil, 0x6e, application)
					response := bertlv.Append(nil, 0x7f49, bertlv.Append(nil, 0x86, point))

					for _, operation := range []struct {
						name string
						p1   byte
						call func(*client.Client, context.Context, protocol.ControlReferenceTemplateTag) (crypto.PublicKey, error)
					}{
						{name: "read", p1: 0x81, call: (*client.Client).ReadPublicKey},
						{name: "generate", p1: 0x80, call: (*client.Client).GenerateAsymmetricKeyPair},
					} {
						t.Run(operation.name, func(t *testing.T) {
							c := newClient(t,
								step{command: []byte{0, 0xca, 0, 0x6e, 0}, response: iso7816.Response{Status: 0x9000, Data: application}},
								step{command: []byte{0, 0x47, operation.p1, 0, 2, byte(algorithm.tag), 0, 0}, response: iso7816.Response{Status: 0x9000, Data: response}},
							)

							public, err := operation.call(c, t.Context(), algorithm.tag)
							if err != nil {
								t.Fatal(err)
							}

							if algorithm.algorithm == protocol.ECDSA {
								key, ok := public.(*ecdsa.PublicKey)
								if !ok {
									t.Fatalf("public key type = %T, want ECDSA", public)
								}

								width := (len(point) - 1) / 2
								//nolint:staticcheck // Go's ECDSA key encoding methods do not support Brainpool curves.
								if key.Curve.Params().Name != curve.name || !bytes.Equal(key.X.Bytes(), point[1:1+width]) || !bytes.Equal(key.Y.Bytes(), point[1+width:]) {
									t.Errorf("ECDSA public key = %+v, want %s generator", key, curve.name)
								}
							} else {
								key, ok := public.(protocol.ECDHPublicKey)
								if !ok {
									t.Fatalf("public key type = %T, want Brainpool ECDH", public)
								}

								if !bytes.Equal(key.CurveOID, curve.oid) || !bytes.Equal(key.PublicPoint, point) {
									t.Errorf("ECDH public key = %+v, want OID %x point %x", key, curve.oid, point)
								}
							}
						})
					}
				})
			}
		})
	}
}
