// Package sm implements OpenPGP Card 3.4.1 static-key secure messaging (Sec. 7.5)
// with AES-128 or AES-256 and 8- or 16-byte MACs. SCP11b lives in iso7816/scp11.
//
// Following Sec. 7.5, key.go describes static-key replacement; record.go handles
// command protection followed by response verification and decryption; crypto.go
// contains CBC and CMAC primitives. transport.go owns the connection and keeps
// each challenge and protected exchange together.
//
// New requires a selected OpenPGP application, provisioned ENC/MAC keys and
// established support for their static-key AES algorithm. It performs no I/O;
// card.OpenSecureMessaging discovers capabilities before constructing the
// transport. Each protected command and its fresh challenge run under one gate;
// the underlying transport handles fragmentation and GET RESPONSE.
//
// SELECT, SELECT DATA, PSO, INTERNAL AUTHENTICATE, GET CHALLENGE and MANAGE
// SECURITY ENVIRONMENT use their specified plaintext form. Unknown commands
// fail before I/O; protected commands are never retried in plaintext.
// Responses to protected commands with a logical Le are authenticated before
// returning plaintext or status. Commands without Le receive an unauthenticated
// status-only response (Sec. 7.5).
//
// To delete both SM keys with client.PutData, write an empty F4 container or
// D1 00 D2 00. WithEmptyPutDataLe requires the nonempty form: key deletion
// requires a status-only response without a logical Le.
//
// An operational ACTIVATE FILE is a no-op and preserves the secure connection.
// After acknowledged TERMINATE DF or SELECT status 6285, ACTIVATE FILE is sent
// in plaintext without a challenge, allowing activation without reconnecting
// (Secs. 7.2.16–17). Successful activation resets the card's keys and closes
// the transport; failed activation leaves the connection available to retry.
package sm

import "errors"

var (
	// ErrInvalidResponse identifies malformed or unauthenticated secure messaging
	// data. The connection is invalidated before the error is returned.
	ErrInvalidResponse = errors.New("openpgp sm: invalid response")
	// ErrAuthentication identifies an incorrect response MAC.
	ErrAuthentication = errors.New("openpgp sm: authentication failed")
)
