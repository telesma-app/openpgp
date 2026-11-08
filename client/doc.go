// Package client sends OpenPGP Card commands through a borrowed APDU transport.
// The caller serializes complete workflows; package card does this for owned
// connections. Only GetDataOdd and Select permit pre-selection use.
// Passwords must already use the card's encoding, including any KDF.
// Commands are never retried.
//
// The command methods in commands.go follow OpenPGP Card 3.4.1, Sec. 7.2,
// from SELECT through MANAGE SECURITY ENVIRONMENT. GET RESPONSE is handled by
// the transport. Typed data-object accessors are grouped by their Sec. 4 topics:
// metadata, application data, KDF, password status, certificates, user interaction
// flags and algorithms. import.go prepares private keys for PUT DATA.
package client
