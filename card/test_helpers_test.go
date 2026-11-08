package card

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport"
)

type exchangeTransport struct {
	exchange func(context.Context, iso7816.Command) (iso7816.Response, error)
	close    func() error
}

func (t *exchangeTransport) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	return t.exchange(ctx, command)
}

func (t *exchangeTransport) Close() error {
	if t.close != nil {
		return t.close()
	}

	return nil
}

func receive[T any](t testing.TB, ch <-chan T, phase string) T {
	t.Helper()

	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", phase)

		var zero T

		return zero
	}
}

type blockingTransport struct {
	started   chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func (t *blockingTransport) Exchange(context.Context, iso7816.Command) (iso7816.Response, error) {
	close(t.started)
	<-t.closed

	return iso7816.Response{}, io.ErrClosedPipe
}

func (t *blockingTransport) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	return nil
}

func newGetterTestDevice(t testing.TB, object protocol.Object, data []byte) *Device {
	t.Helper()

	var calls int

	d := New(&exchangeTransport{exchange: func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
		calls++

		if command.INS != 0xca || command.P1 != byte(object>>8) || command.P2 != byte(object) || len(command.Data) != 0 {
			t.Errorf("command = %+v, want GET DATA %04x", command, uint16(object))
		}

		return success(data), nil
	}})

	t.Cleanup(func() {
		_ = d.Close()

		if calls != 1 {
			t.Errorf("exchanges = %d, want 1", calls)
		}
	})

	return d
}

func checkOperationLifecycle(t *testing.T, data []byte, call func(context.Context, *Device) error) {
	t.Helper()

	callOnce := func(t *testing.T, ctx context.Context, d *Device) error {
		t.Helper()

		completed := make(chan error, 1)
		done := make(chan struct{})

		go func() {
			defer close(done)

			completed <- call(ctx, d)
		}()

		t.Cleanup(func() { receive(t, done, "operation worker completion") })

		return receive(t, completed, "operation completion")
	}

	for _, test := range []struct {
		name        string
		canceled    bool
		invalidated bool
	}{
		{name: "canceled before I/O", canceled: true},
		{name: "ordinary transport failure"},
		{name: "connection invalidated", invalidated: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cause := errors.New("operation transport failed")
				closeCause := errors.New("operation close failed")

				exchangeError := cause
				if test.invalidated {
					exchangeError = &transport.DeviceInvalidatedError{Err: cause}
				}

				var calls, closes int

				d := New(&exchangeTransport{
					exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
						calls++

						if calls == 1 && !test.canceled {
							return iso7816.Response{}, exchangeError
						}

						return success(data), nil
					},
					close: func() error {
						closes++

						if test.invalidated {
							return closeCause
						}

						return nil
					},
				})
				ctx, cancel := context.WithCancel(t.Context())

				defer func() {
					cancel()

					_ = d.Close()
				}()

				if test.canceled {
					cancel()
				}

				err := callOnce(t, ctx, d)

				var invalidated *transport.DeviceInvalidatedError
				switch {
				case test.canceled:
					if !errors.Is(err, context.Canceled) || errors.As(err, &invalidated) || calls != 0 || closes != 0 {
						t.Errorf("canceled operation = %v, exchanges=%d closes=%d; want cancellation without I/O", err, calls, closes)
					}
				case test.invalidated:
					if !errors.As(err, &invalidated) || !errors.Is(err, cause) || !errors.Is(err, closeCause) || calls != 1 || closes != 1 {
						t.Errorf("invalidated operation = %v, exchanges=%d closes=%d; want both causes and one close", err, calls, closes)
					}
				default:
					if !errors.Is(err, cause) || errors.As(err, &invalidated) || calls != 1 || closes != 0 {
						t.Errorf("failed operation = %v, exchanges=%d closes=%d; want ordinary failure without closing", err, calls, closes)
					}
				}

				err = callOnce(t, t.Context(), d)
				if test.invalidated {
					if !errors.Is(err, io.ErrClosedPipe) || calls != 1 || closes != 1 {
						t.Errorf("operation after invalidation = %v, exchanges=%d closes=%d; want closed without I/O", err, calls, closes)
					}

					if err := d.Close(); !errors.Is(err, closeCause) || closes != 1 {
						t.Errorf("repeated Close = %v, closes=%d; want original cause and one close", err, closes)
					}
				} else {
					wantCalls := 2
					if test.canceled {
						wantCalls = 1
					}

					if err != nil || calls != wantCalls || closes != 0 {
						t.Errorf("operation reuse = %v, exchanges=%d closes=%d; want %d exchanges without closing", err, calls, closes, wantCalls)
					}
				}
			})
		})
	}

	t.Run("waits for gate", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var calls, closes int

			d := New(&exchangeTransport{
				exchange: func(context.Context, iso7816.Command) (iso7816.Response, error) {
					calls++
					return success(data), nil
				},
				close: func() error { closes++; return nil },
			})
			ctx, cancel := context.WithCancel(t.Context())

			defer func() {
				cancel()

				_ = d.Close()
			}()

			completed := make(chan error, 1)
			done := make(chan struct{})

			t.Cleanup(func() { receive(t, done, "queued operation worker completion") })

			func() {
				if err := d.lock(t.Context()); err != nil {
					t.Fatal(err)
				}
				defer d.unlock()

				go func() {
					defer close(done)

					completed <- call(ctx, d)
				}()

				synctest.Wait()

				if calls != 0 {
					t.Errorf("exchanges while gate held = %d, want 0", calls)
				}

				select {
				case err := <-completed:
					t.Fatalf("operation returned while gate held: %v", err)
				default:
				}
			}()

			if err := receive(t, completed, "operation after gate release"); err != nil {
				t.Error(err)
			}

			if err := callOnce(t, ctx, d); err != nil {
				t.Error(err)
			}

			if calls != 2 || closes != 0 {
				t.Errorf("operation exchanges=%d closes=%d, want two operations without closing", calls, closes)
			}
		})
	})
}

func success(data []byte) iso7816.Response {
	return iso7816.Response{Data: data, Status: iso7816.StatusSuccess}
}

func decodeHex(t testing.TB, value string) []byte {
	t.Helper()

	data, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func authenticationKeyApplication(attributes []byte) []byte {
	contents := bertlv.Append(nil, 0x4f, []byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 6, 0, 0, 0, 1, 0, 0})
	contents = bertlv.Append(contents, 0x73, bertlv.Append(nil, 0xc3, attributes))

	return bertlv.Append(nil, 0x6e, contents)
}

type brainpoolCardFixture struct {
	name  string
	oid   []byte
	point string
}

// RFC 5639, Sections 3.4, 3.6 and 3.7: these fixed public points are the
// generators, so each is the public key for the test-only private scalar 1.
var brainpoolCardFixtures = []brainpoolCardFixture{
	{
		name: "brainpoolP256r1", oid: []byte{0x2b, 0x24, 3, 3, 2, 8, 1, 1, 7},
		point: "04" +
			"8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262" +
			"547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
	},
	{
		name: "brainpoolP384r1", oid: []byte{0x2b, 0x24, 3, 3, 2, 8, 1, 1, 0x0b},
		point: "04" +
			"1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e" +
			"8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315",
	},
	{
		name: "brainpoolP512r1", oid: []byte{0x2b, 0x24, 3, 3, 2, 8, 1, 1, 0x0d},
		point: "04" +
			"81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822" +
			"7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
	},
}

func checkBrainpoolCardKey(t testing.TB, fixture brainpoolCardFixture, algorithm protocol.Algorithm, public crypto.PublicKey) {
	t.Helper()

	point := decodeHex(t, fixture.point)

	if algorithm == protocol.ECDSA {
		key, ok := public.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("public key type = %T, want ECDSA", public)
		}

		width := (len(point) - 1) / 2
		//nolint:staticcheck // Go's ECDSA key encoding methods do not support Brainpool curves.
		if key.Curve.Params().Name != fixture.name || !bytes.Equal(key.X.Bytes(), point[1:1+width]) || !bytes.Equal(key.Y.Bytes(), point[1+width:]) {
			t.Errorf("ECDSA key = %+v, want %s generator", key, fixture.name)
		}

		return
	}

	key, ok := public.(protocol.ECDHPublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want Brainpool ECDH", public)
	}

	if !bytes.Equal(key.CurveOID, fixture.oid) || !bytes.Equal(key.PublicPoint, point) {
		t.Errorf("ECDH key = %+v, want OID %x point %x", key, fixture.oid, point)
	}
}

func keyApplication(object byte, algorithm protocol.Algorithm, oid []byte) []byte {
	attributes := append([]byte{byte(algorithm)}, oid...)
	data := bertlv.Append(nil, 0x4f, []byte{0xd2, 0x76, 0, 1, 0x24, 1, 3, 4, 0, 1, 0, 0, 0, 1, 0, 0})
	data = bertlv.Append(data, 0x73, bertlv.Append(nil, uint32(object), attributes))

	return bertlv.Append(nil, 0x6e, data)
}

// RFC 8032, Section 7.4, Ed448's one-octet test (message 03), and
// RFC 7748, Section 6.2, Alice's X448 key pair.
const (
	cardEd448Seed      = "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e"
	cardEd448Point     = "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480"
	cardEd448Signature = "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00"
	cardX448Secret     = "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"
	cardX448Point      = "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
	cardSecp256k1Point = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)

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
