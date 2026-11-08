// Package iso7816 exchanges OpenPGP commands over ISO 7816 card connections.
//
// select.go implements application selection (Sec. 7.2.1); exchange.go handles
// GET RESPONSE and command chaining (Secs. 7.2.9 and 7.7). transport.go owns
// the connection and serializes complete exchanges.
package iso7816
