# Testing

Run from the repository root:

```sh
make test-unit
make test-integration
go test ./...
go test -race ./...
go vet ./...
make lint
```

`go test ./...` runs both software suites. Hardware tests are opt-in.

## Hardware setup

Hardware tests require PC/SC. Select one exact reader with
`OPENPGP_TEST_READER` and one exact test with `-run '^TestName$' -count=1`.
PW1/PW3 variables contain hexadecimal password bytes already encoded for the
card, including any KDF. An incorrect password can consume a retry.

Attestation keys and factory/vendor certificates are read-only. Verify that any
factory reset preserves attestation material. Hardware key generation uses only
ordinary SIG key `1`.

## Read tests

```sh
OPENPGP_TEST=1 OPENPGP_TEST_READER='exact reader name' \
    go test -v ./backend/pcsc -run '^TestHardwareRead$' -count=1
```

| Test | Reads and session effects |
| --- | --- |
| `TestHardwareRead` | Metadata and public keys; closing resets the session |
| `TestHardwareChallenge` | Challenge lengths and APDU encodings; closes with `LeaveCard` |
| `TestHardwareReadFile` | Optional EF files after a session reset, before SELECT |
| `TestHardwareReadControlReferenceTemplate` | Existing Yubico key `81` and its certificate; closes with `LeaveCard` |

These tests submit no passwords or data writes. Only `TestHardwareRead` permits
omitting the reader, in which case it inspects all inserted cards.

## Write tests

```sh
OPENPGP_TEST_WRITE=1 OPENPGP_TEST_READER='exact reader name' \
    OPENPGP_TEST_PW3_HEX='<encoded PW3 in hex>' \
    go test -v ./backend/pcsc -run '^TestHardwareWriteCertificates$' -count=1
```

| Test | Credentials | Changes and cleanup |
| --- | --- | --- |
| `TestHardwareWriteCertificates` | PW3 | Replaces/clears AUT, DEC and SIG certificates; restores originals |
| `TestHardwareEmptyPutData` | PW3 | Compares empty PUT DATA forms in every certificate slot; restores originals |
| `TestHardwareImportKey` | PW1 + PW3 | Imports DEC/AUT keys; deletes test keys through C2/C3 and restores attributes |

Import also requires `OPENPGP_TEST_PW1_HEX` and initially empty DEC/AUT keys,
certificates, fingerprints and creation times. Confirm that changing C2/C3 deletes
only the selected slot. Import cleanup performs no factory reset.

## Tests with factory-reset cleanup

These tests erase all OpenPGP keys, passwords, certificates and user data during
cleanup. Use a card authorized for that reset.

```sh
OPENPGP_TEST_WRITE=1 OPENPGP_TEST_RESET=1 \
    OPENPGP_TEST_READER='exact reader name' \
    OPENPGP_TEST_PW1_HEX='<encoded PW1 in hex>' \
    OPENPGP_TEST_PW3_HEX='<encoded PW3 in hex>' \
    go test -v ./backend/pcsc -run '^TestHardwareAES$' -count=1
```

| Test | Operations |
| --- | --- |
| `TestHardwareAES` | Provisions AES-128/256 and checks CBC encipher/decipher |
| `TestHardwareMSE` | Provisions RSA-2048 DEC/AUT keys and checks cross-key operations and binding restoration |
| `TestHardwareMSEP256` | Provisions P-256 DEC/AUT keys and checks cross-key operations and restoration |
| `TestHardwareControlReferenceTemplateGenerate` | Generates ordinary SIG P-256 key `1`, reads it back and signs |

## Known hardware limitations

| Card/setup | Recorded results |
| --- | --- |
| Contactless OpenPGP 3.4 via Token2 Smart Reader | RSA reads, certificates and AES-128 passed; AES-256 rejected with `6700`; no MSE advertised |
| YubiKey 5C NFC 5.8.0 | Certificates and existing attestation key `81` reads passed; no AES or MSE advertised |
| SoloKeys Solo 2 | P-256 MSE, SIG generation and P-256/Ed25519/X25519 imports passed; RSA provisioning returned `6A81`; P-384/P-521 imports returned `6400` |
| RS-Key OpenPGP 3.4 (`FFFE`) | GET CHALLENGE passed beyond the announced 128-byte limit; optional EF files returned `6A82` |

Ed448, X448 and secp256k1 have software verification only.

On 2026-11-08, empty PUT DATA `00 DA 7F 21` through Token2 Smart Reader returned
`9000` while storing unrelated bytes. YubiKey 5.8.0 cleared the object correctly.
For the affected reader, use `client.WithEmptyPutDataLe()`: the verified form
`00 DA 7F 21 00` clears the object in both short and extended workflows. The client
uses case 1 by default and does not detect or retry this successful-but-incorrect
response automatically.
