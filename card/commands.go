package card

import (
	"context"
	"crypto"

	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/protocol"
)

// SELECT (Sec. 7.2.1).

// Select selects OpenPGP and restores default key bindings and data-object
// selection. Existing PrivateKey bindings remain valid. Status 6285 leaves the
// application selected but awaiting ActivateFile.
func (d *Device) Select(ctx context.Context) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.Select(ctx))
}

// VERIFY (Sec. 7.2.2).

// Verify submits borrowed, encoded password bytes without clearing them.
// Incorrect data consumes a retry; empty data queries status.
func (d *Device) Verify(ctx context.Context, reference protocol.PasswordReference, data []byte) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.Verify(ctx, reference, data))
}

// ReferenceStatus queries verification state without consuming a password retry.
func (d *Device) ReferenceStatus(ctx context.Context, reference protocol.PasswordReference) (client.ReferenceStatus, error) {
	if err := d.lock(ctx); err != nil {
		return client.ReferenceStatus{}, err
	}
	defer d.unlock()

	status, err := d.client.ReferenceStatus(ctx, reference)

	return status, d.operationError(err)
}

// ResetSecurityStatus clears a password's verified state.
func (d *Device) ResetSecurityStatus(ctx context.Context, reference protocol.PasswordReference) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.ResetSecurityStatus(ctx, reference))
}

// CHANGE REFERENCE DATA (Sec. 7.2.3).

// ChangeReferenceData replaces PW1 (reference PW1Sign) or PW3 using borrowed,
// encoded values. An incorrect current value consumes a retry.
func (d *Device) ChangeReferenceData(ctx context.Context, reference protocol.PasswordReference, current, replacement []byte) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.ChangeReferenceData(ctx, reference, current, replacement))
}

// RESET RETRY COUNTER (Sec. 7.2.4).

// ResetRetryCounter replaces PW1 using the encoded resetting code. An incorrect
// resetting code consumes a retry. Inputs are borrowed for the call.
func (d *Device) ResetRetryCounter(ctx context.Context, resettingCode, replacement []byte) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.ResetRetryCounter(ctx, resettingCode, replacement))
}

// ResetRetryCounterWithPW3 atomically verifies PW3 and replaces PW1.
// Nil authentication uses the current verification state. Replacement is
// borrowed and already encoded.
func (d *Device) ResetRetryCounterWithPW3(ctx context.Context, replacement []byte, authentication AuthenticationSource) error {
	if err := d.lockAuthenticated(ctx, protocol.PW3, authentication); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.ResetRetryCounterWithPW3(ctx, replacement))
}

// GET DATA (Sec. 7.2.6).

// GetData reads opaque object data using the current verification state.
// An absent object returns an iso7816.APDUError.
func (d *Device) GetData(ctx context.Context, object protocol.Object) ([]byte, error) {
	return d.GetDataWithAuthentication(ctx, object, 0, nil)
}

// GetDataWithAuthentication atomically verifies reference and reads opaque data.
// The caller selects the reference required by the object's access policy:
// PrivateUse3Object requires PW1, PrivateUse4Object requires PW3 (Sec. 5).
// Nil authentication uses the current verification state and ignores reference.
func (d *Device) GetDataWithAuthentication(
	ctx context.Context,
	object protocol.Object,
	reference protocol.PasswordReference,
	authentication AuthenticationSource,
) ([]byte, error) {
	if err := d.lockAuthenticated(ctx, reference, authentication); err != nil {
		return nil, err
	}
	defer d.unlock()

	data, err := d.client.GetData(ctx, object)

	return data, d.operationError(err)
}

// GET NEXT DATA (Sec. 7.2.7).

// GetNextData reads the next certificate occurrence after the current one.
// Use GetCardholderCertificates for an atomic traversal of all three.
func (d *Device) GetNextData(ctx context.Context) ([]byte, error) {
	if err := d.lock(ctx); err != nil {
		return nil, err
	}
	defer d.unlock()

	data, err := d.client.GetNextData(ctx)

	return data, d.operationError(err)
}

// PUT DATA (Sec. 7.2.8).

// PutData atomically verifies reference and replaces the addressed data object.
// The caller selects the reference required by the object's access policy.
// Nil authentication uses the current verification state and ignores reference.
// Data is borrowed for the call.
func (d *Device) PutData(
	ctx context.Context,
	object protocol.Object,
	data []byte,
	reference protocol.PasswordReference,
	authentication AuthenticationSource,
) error {
	if err := d.lockAuthenticated(ctx, reference, authentication); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.PutData(ctx, object, data))
}

// PSO: COMPUTE DIGITAL SIGNATURE (Sec. 7.2.10).

// ComputeDigitalSignature atomically verifies PW1Sign and signs caller-prepared
// input with SIG: DigestInfo for RSA, a digest for ECDSA, or an EdDSA message.
// Nil authentication uses the current verification state. PrivateKey.Sign also
// prepares input and checks output.
func (d *Device) ComputeDigitalSignature(ctx context.Context, data []byte, authentication AuthenticationSource) ([]byte, error) {
	if err := d.lockAuthenticated(ctx, protocol.PW1Sign, authentication); err != nil {
		return nil, err
	}
	defer d.unlock()

	signature, err := d.client.ComputeDigitalSignature(ctx, data)

	return signature, d.operationError(err)
}

// PSO: DECIPHER (Sec. 7.2.11).

// Decipher sends prepared PSO:DECIPHER input through DEC or the AES key in DO D5
// after PW1 verification. The caller supplies the padding indicator or ECDH
// template and performs any KDF. AES input is 02 || whole ciphertext blocks;
// CBC uses a zero IV and returns plaintext without unpadding.
// Verification and deciphering are atomic; nil authentication uses the current
// verification state.
func (d *Device) Decipher(ctx context.Context, data []byte, authentication AuthenticationSource) ([]byte, error) {
	return d.DecipherWithKey(ctx, protocol.ConfidentialityTemplateTag, data, authentication)
}

// DecipherWithKey sends borrowed, prepared asymmetric PSO:DECIPHER input through
// DEC or AUT with PW1 verification in the same workflow. AUT requires MSE support.
// Verification, selection, deciphering and restoration of DEC are atomic.
// Nil authentication uses the current verification state. Failed restoration
// closes and invalidates the Device and returns no plaintext. For AES, use Decipher.
func (d *Device) DecipherWithKey(
	ctx context.Context,
	tag protocol.ControlReferenceTemplateTag,
	data []byte,
	authentication AuthenticationSource,
) ([]byte, error) {
	if err := d.lockAuthenticated(ctx, protocol.PW1, authentication); err != nil {
		return nil, err
	}
	defer d.unlock()

	plaintext, err := d.withKey(ctx, protocol.ConfidentialityTemplateTag, tag, func() ([]byte, error) {
		return d.client.Decipher(ctx, data)
	})

	return plaintext, d.operationError(err)
}

// PSO: ENCIPHER (Sec. 7.2.12).

// Encipher encrypts one or more 16-byte blocks with the AES key in DO D5 after PW1
// verification (reference 82). It uses CBC with a zero IV and no padding.
// Verification and enciphering are atomic; nil authentication uses the current
// verification state. Data is borrowed. The response is 02 || ciphertext,
// ready for Decipher.
func (d *Device) Encipher(ctx context.Context, data []byte, authentication AuthenticationSource) ([]byte, error) {
	if err := d.lockAuthenticated(ctx, protocol.PW1, authentication); err != nil {
		return nil, err
	}
	defer d.unlock()

	ciphertext, err := d.client.Encipher(ctx, data)

	return ciphertext, d.operationError(err)
}

// INTERNAL AUTHENTICATE (Sec. 7.2.13).

// InternalAuthenticate atomically verifies PW1 and sends caller-prepared
// authentication input through AUT. Nil authentication uses the current
// verification state.
func (d *Device) InternalAuthenticate(ctx context.Context, data []byte, authentication AuthenticationSource) ([]byte, error) {
	return d.InternalAuthenticateWithKey(ctx, protocol.AuthenticationTemplateTag, data, authentication)
}

// InternalAuthenticateWithKey signs borrowed, prepared input with AUT or DEC
// with PW1 verification in the same workflow. DEC requires MSE support.
// Verification, key selection, signing and restoration of AUT are atomic.
// Nil authentication uses the current verification state. Failed restoration
// closes and invalidates the Device and returns no signature.
func (d *Device) InternalAuthenticateWithKey(
	ctx context.Context,
	tag protocol.ControlReferenceTemplateTag,
	data []byte,
	authentication AuthenticationSource,
) ([]byte, error) {
	if err := d.lockAuthenticated(ctx, protocol.PW1, authentication); err != nil {
		return nil, err
	}
	defer d.unlock()

	signature, err := d.withKey(ctx, protocol.AuthenticationTemplateTag, tag, func() ([]byte, error) {
		return d.client.InternalAuthenticate(ctx, data)
	})

	return signature, d.operationError(err)
}

// GENERATE ASYMMETRIC KEY PAIR (Sec. 7.2.14).

// GenerateAsymmetricKeyPair reads a slot's attributes and checks decoder support
// before verifying PW3 and replacing the key. These steps run under one gate;
// the password source runs before it. Nil authentication uses the current
// verification state. It does not update fingerprints or generation times.
// Discard old PrivateKey bindings after acknowledgement, including
// client.KeyGenerationError.
func (d *Device) GenerateAsymmetricKeyPair(
	ctx context.Context,
	tag protocol.ControlReferenceTemplateTag,
	authentication AuthenticationSource,
) (crypto.PublicKey, error) {
	password, err := d.lockForAuthentication(ctx, authentication)
	if err != nil {
		return nil, err
	}
	defer d.unlock()
	defer clear(password)

	attributes, err := d.keyAttributes(ctx, tag)
	if err != nil {
		return nil, d.operationError(err)
	}

	if err := attributes.CheckSupported(); err != nil {
		return nil, err
	}

	if authentication != nil {
		err := d.client.Verify(ctx, protocol.PW3, password)
		clear(password)

		if err != nil {
			return nil, d.operationError(err)
		}
	}

	key, err := d.client.GenerateAsymmetricKeyPairWithTemplate(ctx, protocol.ControlReferenceTemplate{Tag: tag}, attributes)

	return key, d.operationError(err)
}

// GenerateAsymmetricKeyPairWithTemplate atomically verifies PW3 and replaces a key.
// Nil authentication uses the current verification state. Attributes must describe
// its current configuration. Decoder support is checked before authentication.
// It does not configure attributes or update fingerprints,
// times or certificates. Discard old bindings after acknowledgement, including
// client.KeyGenerationError.
func (d *Device) GenerateAsymmetricKeyPairWithTemplate(
	ctx context.Context,
	template protocol.ControlReferenceTemplate,
	attributes protocol.AlgorithmAttributes,
	authentication AuthenticationSource,
) (crypto.PublicKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := attributes.CheckSupported(); err != nil {
		return nil, err
	}

	if err := d.lockAuthenticated(ctx, protocol.PW3, authentication); err != nil {
		return nil, err
	}
	defer d.unlock()

	key, err := d.client.GenerateAsymmetricKeyPairWithTemplate(ctx, template, attributes)

	return key, d.operationError(err)
}

// ReadPublicKey atomically reads a slot's attributes and existing public key.
func (d *Device) ReadPublicKey(
	ctx context.Context,
	tag protocol.ControlReferenceTemplateTag,
) (crypto.PublicKey, error) {
	if err := d.lock(ctx); err != nil {
		return nil, err
	}
	defer d.unlock()

	key, err := d.client.ReadPublicKey(ctx, tag)

	return key, d.operationError(err)
}

// ReadPublicKeyWithTemplate reads a key addressed by a short or extended CRT.
// Attributes must describe its current configuration. An unavailable key returns
// an iso7816.APDUError.
func (d *Device) ReadPublicKeyWithTemplate(
	ctx context.Context,
	template protocol.ControlReferenceTemplate,
	attributes protocol.AlgorithmAttributes,
) (crypto.PublicKey, error) {
	if err := d.lock(ctx); err != nil {
		return nil, err
	}
	defer d.unlock()

	key, err := d.client.ReadPublicKeyWithTemplate(ctx, template, attributes)

	return key, d.operationError(err)
}

// GET CHALLENGE (Sec. 7.2.15).

// GetChallenge obtains random challenge bytes from the card.
func (d *Device) GetChallenge(ctx context.Context, length uint32) ([]byte, error) {
	if err := d.lock(ctx); err != nil {
		return nil, err
	}
	defer d.unlock()

	challenge, err := d.client.GetChallenge(ctx, length)

	return challenge, d.operationError(err)
}

// TERMINATE DF (Sec. 7.2.16).

// TerminateDF enters initialization state, disabling normal commands until
// activation. PW3 verification is required unless the card permits termination
// with PW3 blocked or unavailable. Verification and termination are atomic;
// nil authentication uses the current verification state. Reconnect explicitly
// if the card requires reset and selection before ActivateFile (Sec. 7.2.16).
func (d *Device) TerminateDF(ctx context.Context, authentication AuthenticationSource) error {
	if err := d.lockAuthenticated(ctx, protocol.PW3, authentication); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.TerminateDF(ctx))
}

// ACTIVATE FILE (Sec. 7.2.17).

// ActivateFile resets keys, passwords and data to factory defaults in
// initialization state; in operational state it succeeds unchanged. Discard
// PrivateKey bindings after a reset. It can follow TerminateDF directly (Sec. 7.2.17).
func (d *Device) ActivateFile(ctx context.Context) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.ActivateFile(ctx))
}
