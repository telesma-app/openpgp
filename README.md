# telesma-app/openpgp

[![Go Reference](https://pkg.go.dev/badge/github.com/telesma-app/openpgp.svg)](https://pkg.go.dev/github.com/telesma-app/openpgp)
[![Go](https://github.com/telesma-app/openpgp/actions/workflows/go.yml/badge.svg)](https://github.com/telesma-app/openpgp/actions/workflows/go.yml)

Go library for OpenPGP smart cards. It provides low-level commands and card
workflows over [ISO 7816](https://github.com/telesma-app/iso7816) and
[PC/SC](https://github.com/telesma-app/pcsc), including USB CCID tokens and NFC cards.

> [!WARNING]
> This module is under active development. Its public API may change during `v0.x`.

## Features

The library follows OpenPGP Card 3.4.1. Available operations depend on the card
and its access policy.

- Application metadata, capabilities, password status and cardholder data.
- RSA, NIST and Brainpool ECDSA/ECDH, Ed25519 and X25519 public keys and key import.
- Key generation with short or extended Control Reference Templates.
- RSA PKCS#1 v1.5, ECDSA and Ed25519 signing through `crypto.Signer`.
- Raw RSA decryption, ECDH and AES-CBC encipher/decipher commands.
- Password verification, change and retry-counter reset.
- Cardholder certificate reading, replacement and clearing in AUT, DEC and SIG.
- MSE key selection, application termination and activation.
- Static-key AES-128/256 secure messaging and optional EF.DIR/EF.ATR reads.

OpenPGP messages, packets, ASCII armor, fingerprints and password KDF processing
belong to the application. RSA-PSS and RSA-OAEP are unsupported.

## Installation

```sh
go get github.com/telesma-app/openpgp@latest
```

See [`go.mod`](go.mod) for the required Go version.

## Quick start

Open a reader by its exact PC/SC name and read the application metadata:

```go
package main

import (
	"context"
	"fmt"
	"log"

	openpgppcsc "github.com/telesma-app/openpgp/backend/pcsc"
	"github.com/telesma-app/openpgp/card"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()

	connection, err := openpgppcsc.Open(ctx, "exact PC/SC reader name")
	if err != nil {
		return err
	}

	device := card.New(connection)
	defer device.Close()

	application, err := device.GetApplicationRelatedData(ctx)
	if err != nil {
		return err
	}

	fmt.Println(application.AID)
	return nil
}
```

`Open` selects OpenPGP using an exclusive connection. `card.New` takes ownership
of it; closing the device resets the card and clears its authentication state.

## Signing

Bind an existing SIG key and supply the card's encoded PW1 for each signature:

```go
key, err := device.PrivateKey(ctx, protocol.DigitalSignatureTemplateTag)
if err != nil {
	return err
}

authentication := card.AuthenticationSource(func(ctx context.Context) ([]byte, error) {
	return obtainEncodedPW1(ctx)
})
signature, err := key.Signer(ctx, authentication).Sign(nil, digest, crypto.SHA256)
```

`obtainEncodedPW1` is application code. It must return a fresh password buffer;
the signing operation takes ownership and clears it. VERIFY and signing run
under one gate. A nil authentication source uses the current verification state.
Incorrect passwords can consume retries; commands are never retried automatically.

Use `protocol.AuthenticationTemplateTag` for AUT or
`protocol.ConfidentialityTemplateTag` for DEC signing through MSE. For Ed25519,
pass the message with `crypto.Hash(0)`. Every returned signature is checked
against the bound public key. Create a new binding after replacing the key.

## Packages

| Package | Purpose |
| --- | --- |
| [`card`](card) | Owned sessions and serialized card workflows |
| [`client`](client) | Individual commands over a borrowed transport |
| [`backend/pcsc`](backend/pcsc) | Reader discovery and OpenPGP connections |
| [`transport`](transport) | Transport contracts and invalidation errors |
| [`transport/iso7816`](transport/iso7816) | APDU exchanges, chaining and response collection |
| [`transport/sm`](transport/sm) | Static-key OpenPGP AES secure messaging |
| [`protocol`](protocol) | Constants, data models and encodings |

`card.Device` serializes complete workflows. Direct `client.Client` users must
serialize them themselves, including VERIFY followed by a private-key command.
Separate calls on a Device do not form an atomic workflow.

Protected Device operations take an `AuthenticationSource` as their last argument.
The source runs before the operation gate and returns a fresh encoded password
buffer. The operation owns and clears that buffer, and keeps VERIFY and the
protected commands under one gate. A nil source uses the current verification
state. Signing selects PW1Sign, deciphering and authentication select PW1, and
administrative operations select PW3. `PutData` takes an explicit password
reference because access policy depends on the object.

For example, import a key with PW3 verification in the same workflow:

```go
err := device.ImportKey(ctx, protocol.ConfidentialityTemplateTag, privateKey,
	func(ctx context.Context) ([]byte, error) {
		return obtainEncodedPW3(ctx)
	})
```

`obtainEncodedPW3` is application code with the same buffer ownership contract
as `obtainEncodedPW1` above. A failed VERIFY stops the operation without retrying.

Key import preparation and generation decoder checks precede VERIFY. Reading
the current slot attributes, verification and replacement run under one gate.
With explicit attributes, import preparation also precedes the password source.

## Usage notes

- Password inputs must already use the card's encoding, including any configured KDF.
- Key generation and import use the slot's configured algorithm. The application
  manages fingerprints, creation times and certificates after replacement.
- Certificates are opaque bytes; parsing and trust evaluation belong to the caller.
- RSA and ECDH decipher inputs use the card's wire format. ECDH returns a raw
  shared secret; the application performs the OpenPGP KDF and key unwrapping.
- Commands use short APDUs with chaining by default. Pass
  `client.WithExtendedLength()` to `card.New` or `client.NewClient` when the card
  and reader support extended APDUs. SELECT and empty PUT DATA remain short.
- `Device.Exchange` provides raw APDU access. Commands must preserve OpenPGP
  selection and the default SIG/DEC/AUT key bindings.
- Match card status errors as `*iso7816.APDUError` from
  [`telesma-app/iso7816`](https://github.com/telesma-app/iso7816). An interrupted
  exchange may return `*transport.DeviceInvalidatedError`; Device closes that session.

`card.OpenSecureMessaging(ctx, connection, parameters)` reads the selected card's
capabilities, checks the requested static-key AES algorithm, and returns an owned
Device over secure messaging. It takes ownership of the connection only on
success and requires previously provisioned ENC and MAC keys. `sm.New` constructs
the transport without I/O when the caller has already established support.
Some commands, including private-key operations, use plaintext as specified by
OpenPGP Card; protected commands without a logical Le have unauthenticated
status-only responses. See [`transport/sm`](transport/sm) for the exact protection
boundaries.

## Examples

[`examples/inspect`](examples/inspect) reads metadata and existing public keys
without submitting a password or writing data:

```sh
go run ./examples/inspect
go run ./examples/inspect -reader 'exact PC/SC reader name'
```

## Development

Command methods in [`client/commands.go`](client/commands.go) and
[`card/commands.go`](card/commands.go) follow the order in OpenPGP Card 3.4.1,
Section 7.2.

```sh
GOWORK=off go test ./...
GOWORK=off go vet ./...
make lint
```

The normal test suite does not require hardware. See [TESTING.md](TESTING.md)
for hardware test setup, reset scope and known card limitations.

## License

[Apache License 2.0](LICENSE).

## References

- [OpenPGP Smart Card Application 3.4.1](https://www.gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf)
