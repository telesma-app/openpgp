// Package protocol defines OpenPGP Card 3.4.1 commands and data objects.
// It does not encode OpenPGP messages or packets.
//
// Files group definitions by specification topic: directory metadata (Sec. 4.1),
// application identification (Sec. 4.2.1), password formats (Sec. 4.3), data
// objects (Sec. 4.4), historical bytes (Sec. 6), commands and public keys
// (Sec. 7.2), and elliptic curves (Sec. 10). Related enums live with their models.
// Object constants follow the GET DATA and PUT DATA tables; instructions follow
// the command descriptions.
//
// Constructed metadata parsers accept GET DATA with or without the outer template.
// Returned byte slices borrow the input.
package protocol
