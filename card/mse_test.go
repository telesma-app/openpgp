package card

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"errors"
	"io"
	"testing"
	"testing/synctest"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport"
)

func TestWithKeyRestoresDefaultBindings(t *testing.T) {
	for _, test := range []struct {
		name          string
		key           protocol.ControlReferenceTemplateTag
		number        byte
		defaultNumber byte
		function      byte
		cryptoCommand []byte
		call          func(*Device, context.Context, protocol.ControlReferenceTemplateTag, []byte, AuthenticationSource) ([]byte, error)
		defaultCall   func(*Device, context.Context, []byte, AuthenticationSource) ([]byte, error)
	}{
		{
			name: "authenticate DEC", key: protocol.ConfidentialityTemplateTag, number: 2, defaultNumber: 3, function: 0xa4,
			cryptoCommand: []byte{0x00, 0x88, 0x00, 0x00, 0x03, 0x00, 0xaa, 0xbb, 0x00},
			call:          (*Device).InternalAuthenticateWithKey, defaultCall: (*Device).InternalAuthenticate,
		},
		{
			name: "authenticate AUT default", key: protocol.AuthenticationTemplateTag, number: 3, defaultNumber: 3, function: 0xa4,
			cryptoCommand: []byte{0x00, 0x88, 0x00, 0x00, 0x03, 0x00, 0xaa, 0xbb, 0x00},
			call:          (*Device).InternalAuthenticateWithKey, defaultCall: (*Device).InternalAuthenticate,
		},
		{
			name: "decipher AUT", key: protocol.AuthenticationTemplateTag, number: 3, defaultNumber: 2, function: 0xb8,
			cryptoCommand: []byte{0x00, 0x2a, 0x80, 0x86, 0x03, 0x00, 0xaa, 0xbb, 0x00},
			call:          (*Device).DecipherWithKey, defaultCall: (*Device).Decipher,
		},
		{
			name: "decipher DEC default", key: protocol.ConfidentialityTemplateTag, number: 2, defaultNumber: 2, function: 0xb8,
			cryptoCommand: []byte{0x00, 0x2a, 0x80, 0x86, 0x03, 0x00, 0xaa, 0xbb, 0x00},
			call:          (*Device).DecipherWithKey, defaultCall: (*Device).Decipher,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			authentication, decryption := byte(3), byte(2)

			var commands [][]byte

			d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
				raw, err := command.MarshalBinary()
				if err != nil {
					return iso7816.Response{}, err
				}

				commands = append(commands, raw)

				switch command.INS {
				case 0x22:
					if len(command.Data) != 3 {
						t.Errorf("MSE data = %x, want three bytes", command.Data)
						return iso7816.Response{Status: 0x6a80}, nil
					}

					switch command.P2 {
					case 0xa4:
						authentication = command.Data[2]
					case 0xb8:
						decryption = command.Data[2]
					default:
						t.Errorf("MSE function = %02x", command.P2)
					}

					return success(nil), nil
				case 0x88:
					return success([]byte{authentication}), nil
				case 0x2a:
					return success([]byte{decryption}), nil
				default:
					t.Errorf("unexpected instruction %02x", command.INS)
					return iso7816.Response{Status: 0x6d00}, nil
				}
			}})

			t.Cleanup(func() { _ = d.Close() })

			got, err := test.call(d, t.Context(), test.key, []byte{0x00, 0xaa, 0xbb}, nil)
			if err != nil || !bytes.Equal(got, []byte{test.number}) {
				t.Fatalf("WithKey = %x, %v; want key %d", got, err, test.number)
			}

			got, err = test.defaultCall(d, t.Context(), []byte{0x00, 0xaa, 0xbb}, nil)
			if err != nil || !bytes.Equal(got, []byte{test.defaultNumber}) {
				t.Fatalf("default operation = %x, %v; want key %d", got, err, test.defaultNumber)
			}

			want := [][]byte{test.cryptoCommand, test.cryptoCommand}
			if test.number != test.defaultNumber {
				want = [][]byte{
					{0x00, 0x22, 0x41, test.function, 0x03, 0x83, 0x01, test.number},
					test.cryptoCommand,
					{0x00, 0x22, 0x41, test.function, 0x03, 0x83, 0x01, test.defaultNumber},
					test.cryptoCommand,
				}
			}

			if len(commands) != len(want) {
				t.Fatalf("commands = %x, want %x", commands, want)
			}

			for i := range want {
				if !bytes.Equal(commands[i], want[i]) {
					t.Errorf("command %d = %x, want %x", i, commands[i], want[i])
				}
			}

			if authentication != 3 || decryption != 2 {
				t.Errorf("final bindings = IA %d, DEC %d; want IA 3, DEC 2", authentication, decryption)
			}
		})
	}
}

func TestWithKeyFailureRestoration(t *testing.T) {
	set := []byte{0x00, 0x22, 0x41, 0xa4, 0x03, 0x83, 0x01, 0x02}
	command := []byte{0x00, 0x88, 0x00, 0x00, 0x01, 0x01, 0x00}
	restore := []byte{0x00, 0x22, 0x41, 0xa4, 0x03, 0x83, 0x01, 0x03}
	cause := errors.New("connection lost")
	restoreCause := errors.New("restoration interrupted")
	closeErr := errors.New("disconnect failed")

	for _, test := range []struct {
		name        string
		steps       []mseScriptStep
		want        error
		wantAPDU    iso7816.StatusWord
		invalidated bool
	}{
		{
			name:     "setup rejected",
			steps:    []mseScriptStep{{command: set, response: iso7816.Response{Status: 0x6d00}}},
			wantAPDU: 0x6d00,
		},
		{
			name:  "setup acknowledged with unexpected data",
			steps: []mseScriptStep{{command: set, response: success([]byte{0x01})}},
			want:  protocol.ErrInvalidResponse, invalidated: true,
		},
		{
			name:  "setup interrupted",
			steps: []mseScriptStep{{command: set, err: &transport.DeviceInvalidatedError{Err: cause}}},
			want:  cause, invalidated: true,
		},
		{
			name: "crypto rejected and default restored",
			steps: []mseScriptStep{
				{command: set, response: success(nil)},
				{command: command, response: iso7816.Response{Status: 0x6982}},
				{command: restore, response: success(nil)},
			},
			wantAPDU: 0x6982,
		},
		{
			name: "crypto interrupted without restoration",
			steps: []mseScriptStep{
				{command: set, response: success(nil)},
				{command: command, err: &transport.DeviceInvalidatedError{Err: cause}},
			},
			want: cause, invalidated: true,
		},
		{
			name: "restoration rejected after successful crypto",
			steps: []mseScriptStep{
				{command: set, response: success(nil)},
				{command: command, response: success([]byte{0x02})},
				{command: restore, response: iso7816.Response{Status: 0x6f00}},
			},
			wantAPDU: 0x6f00, invalidated: true,
		},
		{
			name: "restoration acknowledged with unexpected data",
			steps: []mseScriptStep{
				{command: set, response: success(nil)},
				{command: command, response: success([]byte{0x02})},
				{command: restore, response: success([]byte{0x01})},
			},
			want: protocol.ErrInvalidResponse, invalidated: true,
		},
		{
			name: "crypto rejection and restoration interruption preserve both causes",
			steps: []mseScriptStep{
				{command: set, response: success(nil)},
				{command: command, response: iso7816.Response{Status: 0x6982}},
				{command: restore, err: &transport.DeviceInvalidatedError{Err: restoreCause}},
			},
			want: restoreCause, wantAPDU: 0x6982, invalidated: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			steps := test.steps
			if !test.invalidated {
				steps = append(steps, mseScriptStep{command: command, response: success([]byte{0x03})})
			}

			d, peer := newMSEDevice(t, closeErr, steps...)

			got, err := d.InternalAuthenticateWithKey(t.Context(), protocol.ConfidentialityTemplateTag, []byte{0x01}, nil)
			if got != nil || err == nil {
				t.Fatalf("WithKey = %x, %v; want nil result and error", got, err)
			}

			if test.want != nil && !errors.Is(err, test.want) {
				t.Errorf("error = %v, want cause %v", err, test.want)
			}

			if test.wantAPDU != 0 {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != test.wantAPDU {
					t.Errorf("error = %v, want APDU error %s", err, test.wantAPDU)
				}
			}

			var invalidated *transport.DeviceInvalidatedError
			if errors.As(err, &invalidated) != test.invalidated {
				t.Errorf("invalidation = %v, want %v", err, test.invalidated)
			}

			if test.invalidated {
				if !errors.Is(err, closeErr) || peer.closes != 1 {
					t.Errorf("error = %v, closes = %d; want close cause and one close", err, peer.closes)
				}

				if _, err := d.InternalAuthenticate(t.Context(), []byte{0x01}, nil); !errors.Is(err, io.ErrClosedPipe) {
					t.Errorf("operation after invalidation = %v, want closed pipe", err)
				}

				if err := d.Close(); !errors.Is(err, closeErr) {
					t.Errorf("Close error = %v, want disconnect failure", err)
				}
			} else {
				if errors.Is(err, closeErr) || peer.closes != 0 {
					t.Errorf("error = %v, closes = %d; rejected command closed the connection", err, peer.closes)
				}

				got, err := d.InternalAuthenticate(t.Context(), []byte{0x01}, nil)
				if err != nil || !bytes.Equal(got, []byte{0x03}) {
					t.Errorf("operation after rejection = %x, %v; want AUT result 03", got, err)
				}
			}
		})
	}
}

func TestWithKeyCancellationAfterSwitchInvalidatesDevice(t *testing.T) {
	for _, test := range []struct {
		name   string
		crypto bool
	}{
		{name: "after MSE acknowledgement"},
		{name: "after crypto acknowledgement", crypto: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			steps := []mseScriptStep{{
				command:  []byte{0x00, 0x22, 0x41, 0xa4, 0x03, 0x83, 0x01, 0x02},
				response: success(nil),
				after:    cancel,
			}}
			if test.crypto {
				steps[0].after = nil
				steps = append(steps, mseScriptStep{
					command:  []byte{0x00, 0x88, 0x00, 0x00, 0x01, 0x01, 0x00},
					response: success([]byte{0x02}), after: cancel,
				})
			}

			closeErr := errors.New("disconnect failed")
			d, peer := newMSEDevice(t, closeErr, steps...)

			got, err := d.InternalAuthenticateWithKey(ctx, protocol.ConfidentialityTemplateTag, []byte{0x01}, nil)

			var invalidated *transport.DeviceInvalidatedError
			if got != nil || !errors.As(err, &invalidated) || !errors.Is(err, context.Canceled) || !errors.Is(err, closeErr) {
				t.Fatalf("WithKey = %x, %v; want nil result, invalidation, cancellation and close cause", got, err)
			}

			if peer.calls != len(steps) || peer.closes != 1 {
				t.Errorf("calls = %d, closes = %d; want %d, 1", peer.calls, peer.closes, len(steps))
			}

			if _, err := d.InternalAuthenticate(t.Context(), []byte{0x01}, nil); !errors.Is(err, io.ErrClosedPipe) {
				t.Errorf("operation after cancellation = %v, want closed pipe", err)
			}
		})
	}
}

func TestTemporaryBindingRestoresBeforeQueuedAUTSigner(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		software := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
		setStarted := make(chan struct{})
		continueSet := make(chan struct{})

		defer func() {
			select {
			case <-continueSet:
			default:
				close(continueSet)
			}
		}()

		binding := byte(3)

		var commands [][]byte

		d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
			raw, err := command.MarshalBinary()
			if err != nil {
				return iso7816.Response{}, err
			}

			commands = append(commands, raw)

			if command.INS == 0x22 {
				if len(command.Data) != 3 {
					t.Errorf("MSE data = %x, want three bytes", command.Data)
					return iso7816.Response{Status: 0x6a80}, nil
				}

				binding = command.Data[2]

				if len(commands) == 1 {
					close(setStarted)
					<-continueSet
				}

				return success(nil), nil
			}

			if command.INS != 0x88 {
				t.Errorf("unexpected instruction %02x", command.INS)
			}

			if binding == 2 {
				return success([]byte{0x02}), nil
			}

			return success(ed25519.Sign(software, command.Data)), nil
		}})

		t.Cleanup(func() { _ = d.Close() })

		key := &PrivateKey{device: d, templateTag: protocol.AuthenticationTemplateTag, publicKey: software.Public()}
		first := make(chan error, 1)

		go func() {
			got, err := d.InternalAuthenticateWithKey(t.Context(), protocol.ConfidentialityTemplateTag, []byte{0x01}, nil)
			if err == nil && !bytes.Equal(got, []byte{0x02}) {
				t.Errorf("temporary operation = %x, want DEC result 02", got)
			}

			first <- err
		}()

		receive(t, setStarted, "temporary MSE setting")

		queued := make(chan error, 1)

		go func() {
			_, err := key.Sign(t.Context(), []byte{0x02}, crypto.Hash(0), nil)
			queued <- err
		}()

		synctest.Wait()

		if len(commands) != 1 {
			t.Fatalf("commands during temporary MSE = %x, want only MSE", commands)
		}

		close(continueSet)

		if err := receive(t, first, "temporary operation restoration"); err != nil {
			t.Fatal(err)
		}

		if err := receive(t, queued, "queued AUT signature"); err != nil {
			t.Fatal(err)
		}

		want := [][]byte{
			{0x00, 0x22, 0x41, 0xa4, 0x03, 0x83, 0x01, 0x02},
			{0x00, 0x88, 0x00, 0x00, 0x01, 0x01, 0x00},
			{0x00, 0x22, 0x41, 0xa4, 0x03, 0x83, 0x01, 0x03},
			{0x00, 0x88, 0x00, 0x00, 0x01, 0x02, 0x00},
		}
		if len(commands) != len(want) {
			t.Fatalf("commands = %x, want %x", commands, want)
		}

		for i := range want {
			if !bytes.Equal(commands[i], want[i]) {
				t.Errorf("command %d = %x, want %x", i, commands[i], want[i])
			}
		}
	})
}

type mseScriptStep struct {
	command  []byte
	response iso7816.Response
	err      error
	after    func()
}

type mseScriptPeer struct {
	t        testing.TB
	steps    []mseScriptStep
	calls    int
	closes   int
	closeErr error
}

func (p *mseScriptPeer) exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	p.t.Helper()
	// Model the real transport's pre-I/O cancellation and closed-session boundary.
	if err := ctx.Err(); err != nil {
		return iso7816.Response{}, err
	}

	if p.closes != 0 {
		return iso7816.Response{}, io.ErrClosedPipe
	}

	if p.calls == len(p.steps) {
		p.t.Errorf("unexpected instruction %02x", command.INS)
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	step := p.steps[p.calls]
	p.calls++

	raw, err := command.MarshalBinary()
	if err != nil {
		return iso7816.Response{}, err
	}

	if !bytes.Equal(raw, step.command) {
		p.t.Errorf("command %d = %x, want %x", p.calls, raw, step.command)
	}

	if step.after != nil {
		step.after()
	}

	return step.response, step.err
}

func newMSEDevice(t testing.TB, closeErr error, steps ...mseScriptStep) (*Device, *mseScriptPeer) {
	t.Helper()
	peer := &mseScriptPeer{t: t, steps: steps, closeErr: closeErr}
	d := New(&exchangeTransport{
		exchange: peer.exchange,
		close:    func() error { peer.closes++; return peer.closeErr },
	})

	t.Cleanup(func() {
		_ = d.Close()

		if peer.calls != len(peer.steps) {
			t.Errorf("exchanges = %d, want %d", peer.calls, len(peer.steps))
		}

		if peer.closes != 1 {
			t.Errorf("Close calls = %d, want 1", peer.closes)
		}
	})

	return d, peer
}
