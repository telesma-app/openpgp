package client

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

// SELECT (Sec. 7.2.1).

// Select selects OpenPGP, resetting data-object pointers and key bindings.
// Optional FCI is ignored (Sec. 7.2.1). Status 6285 leaves the application selected
// but awaiting ActivateFile.
func (c *Client) Select(ctx context.Context) error {
	_, err := c.exchange(ctx, protocol.SelectCommand())
	if err != nil {
		return fmt.Errorf("openpgp: SELECT: %w", err)
	}

	return nil
}

// VERIFY (Sec. 7.2.2).

// ReferenceStatus is the result of an empty VERIFY. Retries is meaningful only
// when Verified is false and the card returned an explicit 63Cx status word.
// A blocked reference reported as 6983 remains an iso7816.APDUError.
type ReferenceStatus struct {
	Verified bool
	Retries  int
}

// ReferenceDataError reports a password failure and retry count, preserving
// the APDU error without password data. Resetting-code failures use reference 0.
type ReferenceDataError struct {
	Reference protocol.PasswordReference
	Retries   int
	Status    iso7816.StatusWord
}

func (e *ReferenceDataError) Error() string {
	return fmt.Sprintf("openpgp: reference %02x verification failed (%d retries, SW=%s)", byte(e.Reference), e.Retries, e.Status)
}

func (e *ReferenceDataError) Unwrap() error {
	return &iso7816.APDUError{SW1: e.Status.SW1(), SW2: e.Status.SW2()}
}

// Verify sends password bytes in the card's encoding, including any KDF.
// Empty data queries status without consuming a retry; incorrect data can consume
// one. PW1Sign authorizes PSO:CDS, PW1 decipher/authentication, and PW3 administration.
func (c *Client) Verify(ctx context.Context, reference protocol.PasswordReference, data []byte) error {
	return c.referenceCommand(ctx, protocol.Verify, 0, reference, data)
}

// ReferenceStatus queries verification state without submitting a password.
func (c *Client) ReferenceStatus(ctx context.Context, reference protocol.PasswordReference) (ReferenceStatus, error) {
	err := c.Verify(ctx, reference, nil)
	if err == nil {
		return ReferenceStatus{Verified: true}, nil
	}

	var referenceError *ReferenceDataError
	if errors.As(err, &referenceError) {
		return ReferenceStatus{Retries: referenceError.Retries}, nil
	}

	return ReferenceStatus{}, err
}

// ResetSecurityStatus clears verification state without submitting a password.
func (c *Client) ResetSecurityStatus(ctx context.Context, reference protocol.PasswordReference) error {
	return c.referenceCommand(ctx, protocol.Verify, 0xff, reference, nil)
}

// CHANGE REFERENCE DATA (Sec. 7.2.3).

// ChangeReferenceData replaces PW1 (reference PW1Sign) or PW3 with encoded values,
// concatenated without delimiters or padding. Incorrect current data can consume
// a retry. PW1 changes affect both verification modes.
func (c *Client) ChangeReferenceData(ctx context.Context, reference protocol.PasswordReference, current, replacement []byte) error {
	data := make([]byte, 0, len(current)+len(replacement))
	data = append(data, current...)

	data = append(data, replacement...)
	defer clear(data)

	return c.referenceCommand(ctx, protocol.ChangeReferenceData, 0, reference, data)
}

// RESET RETRY COUNTER (Sec. 7.2.4).

// ResetRetryCounter replaces PW1 using the resetting code. Incorrect resetting
// data can consume a resetting-code retry. Values are already encoded.
func (c *Client) ResetRetryCounter(ctx context.Context, resettingCode, replacement []byte) error {
	data := make([]byte, 0, len(resettingCode)+len(replacement))
	data = append(data, resettingCode...)

	data = append(data, replacement...)
	defer clear(data)

	return c.referenceCommand(ctx, protocol.ResetRetryCounter, 0, protocol.PW1Sign, data)
}

// ResetRetryCounterWithPW3 replaces PW1 with encoded data and resets its retry
// counter. PW3 must already be verified.
func (c *Client) ResetRetryCounterWithPW3(ctx context.Context, replacement []byte) error {
	return c.referenceCommand(ctx, protocol.ResetRetryCounter, 0x02, protocol.PW1Sign, replacement)
}

// SELECT DATA (Sec. 7.2.5).

// SelectData selects a zero-based occurrence of an object (Sec. 7.2.5).
// For cardholder certificates, occurrence 0 is AUT, 1 is DEC, and 2 is SIG.
// A subsequent GetData/PutData must run in the same serialized workflow.
func (c *Client) SelectData(ctx context.Context, object protocol.Object, occurrence byte) error {
	var tag []byte
	if object > 0xff {
		tag = append(tag, byte(object>>8))
	}

	tag = append(tag, byte(object))
	data := bertlv.Append(nil, 0x60, bertlv.Append(nil, 0x5c, tag))

	_, err := c.exchange(ctx, iso7816.Command{
		INS: byte(protocol.SelectData), P1: occurrence, P2: 0x04,
		Data: data, Le: c.responseLength(), Encoding: c.encoding,
	})
	if err != nil {
		return fmt.Errorf("openpgp: SELECT DATA %04x occurrence %d: %w", uint16(object), occurrence, err)
	}

	// Optional control parameters are not needed by the application (7.2.5).
	return nil
}

// GET DATA (Sec. 7.2.6).

// GetData returns an object's bytes, including BER-TLV for constructed objects.
// Unavailable objects return an iso7816.APDUError. SELECT DATA determines the
// current occurrence of objects such as cardholder certificates.
func (c *Client) GetData(ctx context.Context, object protocol.Object) ([]byte, error) {
	response, err := c.exchange(ctx, iso7816.Command{
		INS: byte(protocol.GetData), P1: byte(object >> 8), P2: byte(object),
		Le: c.responseLength(), Encoding: c.encoding,
	})
	if err != nil {
		return nil, fmt.Errorf("openpgp: GET DATA %04x: %w", uint16(object), err)
	}

	return response.Data, nil
}

// GetDataOdd reads opaque objects from EF.DIR or EF.ATR/INFO. Access is guaranteed
// directly after reset, before selection, on cards announcing this capability
// (Secs. 4.1.1, 4.1.3 and 7.2.6). The caller establishes that state.
// Unavailable files return an iso7816.APDUError.
func (c *Client) GetDataOdd(ctx context.Context, file protocol.FileID) ([]byte, error) {
	response, err := c.exchange(ctx, iso7816.Command{
		INS: byte(protocol.GetDataOdd), P1: byte(file >> 8), P2: byte(file),
		Data: []byte{0x5c, 0x00}, Le: c.responseLength(), Encoding: c.encoding,
	})
	if err != nil {
		return nil, fmt.Errorf("openpgp: GET DATA (CB) file %04x: %w", uint16(file), err)
	}

	return response.Data, nil
}

// GET NEXT DATA (Sec. 7.2.7).

// GetNextData reads the next DO 7F21 certificate occurrence after the current one.
// Contents are opaque and may be empty; the new occurrence remains current.
func (c *Client) GetNextData(ctx context.Context) ([]byte, error) {
	response, err := c.exchange(ctx, iso7816.Command{
		INS: byte(protocol.GetNextData), P1: 0x7f, P2: 0x21,
		Le: c.responseLength(), Encoding: c.encoding,
	})
	if err != nil {
		return nil, fmt.Errorf("openpgp: GET NEXT DATA 7f21: %w", err)
	}

	return response.Data, nil
}

// PUT DATA (Sec. 7.2.8).

// PutData replaces an object's value, usually after PW3 verification.
// Empty data clears variable-length contents with a four-byte APDU, without
// Lc or Le (Sec. 7.2.8). WithEmptyPutDataLe selects the reader compatibility form.
func (c *Client) PutData(ctx context.Context, object protocol.Object, data []byte) error {
	command := iso7816.Command{
		INS: byte(protocol.PutData), P1: byte(object >> 8), P2: byte(object),
		Data: data, Encoding: c.encoding,
	}
	if len(data) == 0 {
		command.Encoding = iso7816.EncodingShort
		if c.emptyPutDataLe {
			command.Le = 256
		}
	}

	response, err := c.exchange(ctx, command)
	if err != nil {
		return fmt.Errorf("openpgp: PUT DATA %04x: %w", uint16(object), err)
	}

	return emptyResponse(response)
}

// ImportKeyData sends a complete, preencoded Extended Header List (4D) after
// PW3 verification. Data includes the CRT and must correspond to template,
// which identifies the request in errors. Data is borrowed unchanged for the
// call; the caller owns and clears it. A malformed acknowledgement returns
// KeyImportError. Transport failures have unknown effects.
func (c *Client) ImportKeyData(
	ctx context.Context,
	template protocol.ControlReferenceTemplate,
	data []byte,
) error {
	response, err := c.exchange(ctx, iso7816.Command{
		INS: byte(protocol.PutDataOdd), P1: 0x3f, P2: 0xff,
		Data: data, Encoding: c.encoding,
	})
	if err != nil {
		return fmt.Errorf("openpgp: IMPORT KEY CRT %x: %w", template.Bytes(), err)
	}

	if err := emptyResponse(response); err != nil {
		return &KeyImportError{Template: template, Err: err}
	}

	return nil
}

// PSO: COMPUTE DIGITAL SIGNATURE (Sec. 7.2.10).

// ComputeDigitalSignature signs DigestInfo (RSA), a digest (ECDSA), or
// algorithm-specific EdDSA input using SIG. RSA adds PKCS#1 v1.5 padding;
// ECDSA returns r || s. Verify PW1Sign first; each signature may consume it.
func (c *Client) ComputeDigitalSignature(ctx context.Context, data []byte) ([]byte, error) {
	return c.cryptoCommand(ctx, protocol.PerformSecurityOperation, 0x9e, 0x9a, data)
}

// PSO: DECIPHER (Sec. 7.2.11).

// Decipher sends prepared PSO:DECIPHER input after PW1 verification:
//   - RSA: 00 || ciphertext; removes PKCS#1 v1.5 padding.
//   - ECDH: A6 { 7F49 { 86 { peer key } } }; returns the raw shared secret.
//   - AES: 02 || whole ciphertext blocks; CBC with zero IV and no unpadding.
//
// RSA and ECDH use the current MSE binding, DEC by default. AES uses AESKeyObject.
// The caller handles the OpenPGP KDF. RSA OAEP is unsupported.
func (c *Client) Decipher(ctx context.Context, data []byte) ([]byte, error) {
	return c.cryptoCommand(ctx, protocol.PerformSecurityOperation, 0x80, 0x86, data)
}

// PSO: ENCIPHER (Sec. 7.2.12).

// Encipher encrypts one or more 16-byte blocks using AESKeyObject after PW1
// verification (reference 82). CBC uses a zero IV and no padding. The response
// is 02 || ciphertext (Sec. 7.2.12).
func (c *Client) Encipher(ctx context.Context, data []byte) ([]byte, error) {
	return c.cryptoCommand(ctx, protocol.PerformSecurityOperation, 0x86, 0x80, data)
}

// INTERNAL AUTHENTICATE (Sec. 7.2.13).

// InternalAuthenticate signs caller-encoded authentication input using the
// current MSE binding, AUT by default. Verify PW1 first. RSA input receives
// PKCS#1 v1.5 padding; ECDSA input is a digest and output is r || s.
func (c *Client) InternalAuthenticate(ctx context.Context, data []byte) ([]byte, error) {
	return c.cryptoCommand(ctx, protocol.InternalAuthenticate, 0, 0, data)
}

// GENERATE ASYMMETRIC KEY PAIR (Sec. 7.2.14).

// KeyGenerationError means the card acknowledged key replacement but its public
// key response could not be parsed. Retrying would replace the key again.
// A transport failure has an unknown effect and does not use this type.
type KeyGenerationError struct {
	Template protocol.ControlReferenceTemplate
	Err      error
}

func (e *KeyGenerationError) Error() string {
	return fmt.Sprintf("openpgp: key CRT %x generated, but public key response could not be decoded: %v", e.Template.Bytes(), e.Err)
}

func (e *KeyGenerationError) Unwrap() error {
	return e.Err
}

// GenerateAsymmetricKeyPair reads a slot's attributes, then replaces its key
// after PW3 verification. It does not update fingerprints, times or certificates.
func (c *Client) GenerateAsymmetricKeyPair(
	ctx context.Context,
	tag protocol.ControlReferenceTemplateTag,
) (crypto.PublicKey, error) {
	attributes, err := c.keyAttributes(ctx, tag)
	if err != nil {
		return nil, err
	}

	return c.GenerateAsymmetricKeyPairWithTemplate(ctx, protocol.ControlReferenceTemplate{Tag: tag}, attributes)
}

// GenerateAsymmetricKeyPairWithTemplate replaces a key after PW3 verification.
// Attributes must describe its current configuration (Sec. 7.2.14). Decoder
// support is checked before generation. It does not configure attributes or
// update fingerprints, times or certificates.
// Invalid acknowledged output returns KeyGenerationError with the requested CRT.
func (c *Client) GenerateAsymmetricKeyPairWithTemplate(
	ctx context.Context,
	template protocol.ControlReferenceTemplate,
	attributes protocol.AlgorithmAttributes,
) (crypto.PublicKey, error) {
	if err := attributes.CheckSupported(); err != nil {
		return nil, err
	}

	data, err := c.keyCommand(ctx, template, 0x80)
	if err != nil {
		return nil, err
	}

	publicKey, err := protocol.ParsePublicKey(attributes, data)
	if err != nil {
		return nil, &KeyGenerationError{Template: template, Err: err}
	}

	return publicKey, nil
}

// ReadPublicKey reads a standard slot's attributes and existing public key.
// An empty slot returns an iso7816.APDUError.
func (c *Client) ReadPublicKey(
	ctx context.Context,
	tag protocol.ControlReferenceTemplateTag,
) (crypto.PublicKey, error) {
	attributes, err := c.keyAttributes(ctx, tag)
	if err != nil {
		return nil, err
	}

	return c.ReadPublicKeyWithTemplate(ctx, protocol.ControlReferenceTemplate{Tag: tag}, attributes)
}

// ReadPublicKeyWithTemplate reads an existing key using the supplied CRT.
// Attributes must describe its current configuration. Additional key references
// and their attribute objects are card-specific (Sec. 7.2.14).
func (c *Client) ReadPublicKeyWithTemplate(
	ctx context.Context,
	template protocol.ControlReferenceTemplate,
	attributes protocol.AlgorithmAttributes,
) (crypto.PublicKey, error) {
	data, err := c.keyCommand(ctx, template, 0x81)
	if err != nil {
		return nil, err
	}

	return protocol.ParsePublicKey(attributes, data)
}

// GET CHALLENGE (Sec. 7.2.15).

// GetChallenge requests random bytes from the card. Lengths >= 256 use extended
// APDUs, requiring card and reader support; Sec. 7.2.15 limits short Le to 01..FF.
// Use crypto/rand for host randomness.
func (c *Client) GetChallenge(ctx context.Context, length uint32) ([]byte, error) {
	encoding := c.encoding
	if length >= 256 {
		encoding = iso7816.EncodingExtended
	}

	response, err := c.exchange(ctx, iso7816.Command{
		INS: byte(protocol.GetChallenge), Le: length, Encoding: encoding,
	})
	if err != nil {
		return nil, fmt.Errorf("openpgp: GET CHALLENGE: %w", err)
	}

	if uint32(len(response.Data)) != length {
		return nil, fmt.Errorf("%w: GET CHALLENGE returned %d bytes, want %d", protocol.ErrInvalidResponse, len(response.Data), length)
	}

	return response.Data, nil
}

// TERMINATE DF (Sec. 7.2.16).

// TerminateDF enters initialization state (Sec. 7.2.16). This optional command
// is announced in the historical bytes. Verify PW3 first unless it is blocked
// or unavailable. The card is not reset.
func (c *Client) TerminateDF(ctx context.Context) error {
	response, err := c.exchange(ctx, iso7816.Command{
		INS: byte(protocol.TerminateDF), Encoding: c.encoding,
	})
	if err != nil {
		return fmt.Errorf("openpgp: TERMINATE DF: %w", err)
	}

	return emptyResponse(response)
}

// ACTIVATE FILE (Sec. 7.2.17).

// ActivateFile resets keys, passwords and data to factory defaults in
// initialization state; in operational state it succeeds unchanged (Sec. 7.2.17).
// This optional command is announced in the historical bytes and can follow
// TerminateDF directly.
func (c *Client) ActivateFile(ctx context.Context) error {
	response, err := c.exchange(ctx, iso7816.Command{
		INS: byte(protocol.ActivateFile), Encoding: c.encoding,
	})
	if err != nil {
		return fmt.Errorf("openpgp: ACTIVATE FILE: %w", err)
	}

	return emptyResponse(response)
}

// MANAGE SECURITY ENVIRONMENT (Sec. 7.2.18).

// ManageSecurityEnvironment assigns a DEC or AUT KeyReference to INTERNAL
// AUTHENTICATE (AuthenticationTemplateTag) or asymmetric PSO:DECIPHER
// (ConfidentialityTemplateTag), without changing keys or attributes.
// The binding lasts until reassignment, reset or SELECT (Sec. 7.2.18).
// Serialize selection and use; restore defaults before workflows requiring them.
// An error matching protocol.ErrInvalidResponse may follow an applied MSE:
// restore a known binding or discard the connection.
func (c *Client) ManageSecurityEnvironment(
	ctx context.Context,
	operation protocol.ControlReferenceTemplateTag,
	key protocol.KeyReference,
) error {
	response, err := c.exchange(ctx, iso7816.Command{
		INS: byte(protocol.ManageSecurityEnvironment), P1: 0x41, P2: byte(operation),
		Data: []byte{0x83, 1, byte(key)}, Encoding: c.encoding,
	})
	if err != nil {
		return fmt.Errorf("openpgp: MANAGE SECURITY ENVIRONMENT %02x key %02x: %w", byte(operation), byte(key), err)
	}

	return emptyResponse(response)
}

// Command exchange helpers.

func (c *Client) referenceCommand(ctx context.Context, instruction protocol.Instruction, p1 byte, reference protocol.PasswordReference, data []byte) error {
	response, err := c.transport.Exchange(ctx, iso7816.Command{
		INS: byte(instruction), P1: p1, P2: byte(reference),
		Data: data, Encoding: c.encoding,
	})
	if err != nil {
		return err
	}

	if response.Status&0xfff0 == 0x63c0 {
		if err := emptyResponse(response); err != nil {
			return err
		}

		if instruction == protocol.ResetRetryCounter && p1 == 0 {
			reference = 0
		}

		return &ReferenceDataError{Reference: reference, Retries: int(response.Status & 0xf), Status: response.Status}
	}

	if err := response.APDUError(); err != nil {
		return err
	}

	return emptyResponse(response)
}

func (c *Client) cryptoCommand(ctx context.Context, instruction protocol.Instruction, p1, p2 byte, data []byte) ([]byte, error) {
	response, err := c.exchange(ctx, iso7816.Command{
		INS: byte(instruction), P1: p1, P2: p2,
		Data: data, Le: c.responseLength(), Encoding: c.encoding,
	})
	if err != nil {
		return nil, fmt.Errorf("openpgp: cryptographic command %02x/%02x%02x: %w", byte(instruction), p1, p2, err)
	}

	return response.Data, nil
}

func (c *Client) keyCommand(
	ctx context.Context,
	template protocol.ControlReferenceTemplate,
	p1 byte,
) ([]byte, error) {
	data := template.Bytes()

	response, err := c.exchange(ctx, iso7816.Command{
		INS: byte(protocol.GenerateAsymmetricKeyPair), P1: p1,
		Data: data, Le: c.responseLength(), Encoding: c.encoding,
	})
	if err != nil {
		return nil, fmt.Errorf("openpgp: key CRT %x operation %02x: %w", data, p1, err)
	}

	return response.Data, nil
}
