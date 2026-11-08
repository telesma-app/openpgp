# Testing

Run module checks independently of the parent Go workspace:

```sh
GOWORK=off go test ./...
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
make lint
```

Software tests use scripted cards and cryptographic vectors. Hardware tests in
[`backend/pcsc`](backend/pcsc) are opt-in and require a working PC/SC service.

Ed448, X448 and secp256k1 support is verified by software tests only. Ed448 and
X448 use RFC 8032 and RFC 7748 vectors, including exact OpenPGP Card import
encoding; secp256k1 uses the SEC 2 generator and an independently fixed ECDSA
signature. Read, generation and authenticated import workflows run against
scripted cards. These curves have not been validated on hardware.

## Hardware rules

Attestation keys and factory/vendor certificates are read-only across OpenPGP,
PIV and FIDO. Never generate, import, overwrite or delete them. Before a factory
reset, verify its scope and that it preserves attestation material. Key reference
`81` generation in software tests uses scripted peers; hardware generation uses
only the ordinary SIG key `1`.

Always select one exact reader for write tests. Supply PW1/PW3 as hexadecimal
bytes already encoded for the card, including any KDF. An incorrect password can
consume a retry.

## Read tests

```sh
GOWORK=off OPENPGP_TEST=1 OPENPGP_TEST_READER='exact PC/SC reader name' \
    go test -v ./backend/pcsc -run '^TestHardwareRead$' -count=1
```

| Test | Reads and session effects |
| --- | --- |
| `TestHardwareRead` | Metadata and public keys; closing resets the card session |
| `TestHardwareChallenge` | Challenge lengths and APDU encodings; closes with `LeaveCard` |
| `TestHardwareReadFile` | EF.DIR and EF.ATR/INFO after an ordinary session reset, before SELECT |
| `TestHardwareReadControlReferenceTemplate` | Existing Yubico key `81`, compared with its attestation certificate; closes with `LeaveCard` |

These tests submit no passwords and write no data. `OPENPGP_TEST_READER` is
optional only for `TestHardwareRead`, which otherwise inspects all inserted
cards. Select each test by its exact name with `-run`.

Challenge diagnostics include requests above the card's announced limit and
raw short Le=00 probes; these interoperability probes are not card requirements.
Logs omit random bytes and file contents. Attestation key comparison does not
evaluate certificate-chain trust.

## Write tests

Certificate tests require PW3 and restore the original certificate contents:

```sh
GOWORK=off OPENPGP_TEST_WRITE=1 OPENPGP_TEST_READER='exact test reader name' \
    OPENPGP_TEST_PW3_HEX='<encoded PW3 in hex>' \
    go test -v ./backend/pcsc -run '^TestHardwareWriteCertificates$' -count=1
```

| Test | Changes and cleanup |
| --- | --- |
| `TestHardwareWriteCertificates` | Replaces/clears AUT, DEC and SIG certificates and checks GET NEXT DATA; restores originals |
| `TestHardwareEmptyPutData` | Compares case 1, 2S and 2E empty PUT DATA in every certificate slot; restores originals after each workflow |
| `TestHardwareImportKey` | Imports ordinary DEC/AUT keys; deletes test keys through C2/C3 and restores original attributes |

`TestHardwareImportKey` also requires `OPENPGP_TEST_PW1_HEX` and initially empty
DEC/AUT keys, certificates, fingerprints and creation times. Verify that the
card's attribute setters delete only the selected slot. Cleanup performs no
factory reset.

## Tests with factory-reset cleanup

These tests require both write and reset flags. Cleanup erases all OpenPGP keys,
passwords and data objects, returning the application to factory defaults.
Use only a card authorized for that reset.

```sh
GOWORK=off OPENPGP_TEST_WRITE=1 OPENPGP_TEST_RESET=1 \
    OPENPGP_TEST_READER='exact test reader name' \
    OPENPGP_TEST_PW1_HEX='<encoded PW1 in hex>' \
    OPENPGP_TEST_PW3_HEX='<encoded PW3 in hex>' \
    go test -v ./backend/pcsc -run '^TestHardwareAES$' -count=1
```

| Test | Coverage |
| --- | --- |
| `TestHardwareAES` | AES-128/256 provisioning and CBC encipher/decipher against host results |
| `TestHardwareMSE` | DEC/AUT RSA-2048 cross-key signing, decryption and default-binding restoration |
| `TestHardwareMSEP256` | ECDH-P256 DEC and ECDSA-P256 AUT cross-key operations and restoration |
| `TestHardwareControlReferenceTemplateGenerate` | Standard SIG P-256 generation with extended CRT key `1`, public readback and signing |

Cards missing the required advertised AES or MSE capability are skipped before
authentication and provisioning. The P-256 MSE test explicitly interprets the
DEC ECDH point as an ECDSA verification key; this does not extend the library's
ECDH signing contract.

## Recorded hardware results

These observations describe tested cards, not guarantees for other firmware.

| Card | Results and limitations |
| --- | --- |
| Contactless OpenPGP 3.4 card via Token2 Smart Reader | RSA public reads, certificate workflows and AES-128 passed; AES-256 key rejected with `6700`; no MSE advertised |
| YubiKey 5C NFC 5.8.0 | Certificate workflows and extended-CRT reading of existing attestation key `81` passed; no AES or MSE advertised |
| SoloKeys Solo 2 | P-256 MSE, SIG generation, P-256/Ed25519/X25519 imports passed; RSA provisioning returned `6A81`; P-384/P-521 imports returned `6400` |
| RS-Key test token, OpenPGP 3.4 (`FFFE`) | GET CHALLENGE passed beyond the announced 128-byte limit, including 256-byte short and extended requests; optional EF files returned `6A82` |

On 2026-11-08, 36 empty PUT DATA scenarios were checked through Token2 Smart
Reader and on YubiKey 5.8.0: three APDU forms in short and extended certificate
workflows for AUT, DEC and SIG on each setup. YubiKey 5.7.4 was not used.
All commands returned `9000`, with the same results across slots and workflows:

| Empty PUT DATA APDU | Through Token2 Smart Reader | YubiKey 5.8.0 |
| --- | --- | --- |
| `00 DA 7F 21` | Stored 217–474 unrelated bytes instead of clearing | Cleared |
| `00 DA 7F 21 00` | Cleared | Cleared |
| `00 DA 7F 21 00 00 00` | Cleared | Cleared |

The original certificates were restored. A separate check confirmed matching
certificate hashes, KDF data and PIN retry counters before and after testing.

The client omits Le by default, as specified in Section 7.2.8.
`client.WithEmptyPutDataLe()` selects the verified five-byte short form with
Le=256 for empty PUT DATA in both encoding modes. The certificate write and
restoration tests select this option explicitly so they also work through the
affected reader. No automatic detection or retry can handle the observed case 1
behavior: it returns success while changing the stored contents. Raw `Exchange`
preserves the caller's encoding for explicit interoperability probes.

Select Solo 2's passing import profiles with:

```sh
GOWORK=off OPENPGP_TEST_WRITE=1 OPENPGP_TEST_READER='exact test reader name' \
    OPENPGP_TEST_PW1_HEX='<encoded PW1 in hex>' \
    OPENPGP_TEST_PW3_HEX='<encoded PW3 in hex>' \
    go test -v ./backend/pcsc \
    -run '^TestHardwareImportKey/(short|extended)/(AUT_P256|AUT_Ed25519|DEC_P256|DEC_X25519)$' \
    -count=1
```

The P-384/P-521 execution errors remain test failures. Targeted import cleanup
confirmed empty DEC/AUT slots and metadata, restored attributes and unchanged
password retry counters. No attestation material was written.

## Accepted RSA exponent limit

The typed public-key decoder uses Go's `crypto/rsa.PublicKey` representation
and rejects RSA public exponents with more than 31 significant bits. This is an
interoperability restriction beyond [OpenPGP Card 3.4.1, Sec. 7.2.14](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf),
which permits other exponent values. Decoding returns `ErrUnsupportedAlgorithm`;
if key generation was already acknowledged, it is wrapped in `KeyGenerationError`.
The generated key may therefore exist even when the typed API returns an error.

Accepted on 2026-11-08: no concrete card or required workflow needing a larger
exponent has been identified. The current representation and rejection behavior
are accepted and are not release blockers. Revisit this decision when a concrete
interoperability case requires a larger exponent; that case can justify a separate
wire-level public-key representation. Raw APDU exchange remains available.
