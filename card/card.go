package card

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/client"
	"github.com/telesma-app/openpgp/transport"
)

// Device owns a selected OpenPGP connection and serializes complete card
// operations. Create it with New. A Device must not be copied.
type Device struct {
	transport transport.Device
	client    *client.Client
	mu        chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

var _ transport.Device = (*Device)(nil)

// New takes ownership of transport without I/O. OpenPGP must be selected with
// default SIG/DEC/AUT bindings, as after SELECT. Stop using transport directly.
// Options configure command encoding.
func New(transport transport.Device, options ...client.Option) *Device {
	return &Device{
		transport: transport,
		client:    client.NewClient(transport, options...),
		mu:        make(chan struct{}, 1),
		closed:    make(chan struct{}),
	}
}

// Exchange sends a complete APDU through the same gate as card workflows and
// returns the final status word without interpretation. Commands must leave
// OpenPGP selected and the default SIG/DEC/AUT key bindings intact.
func (d *Device) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	if err := d.lock(ctx); err != nil {
		return iso7816.Response{}, err
	}
	defer d.unlock()

	response, err := d.transport.Exchange(ctx, command)

	return response, d.operationError(err)
}

// Close prevents new operations and closes the transport once. It does not
// acquire the operation gate. Waiting callers return io.ErrClosedPipe; active
// I/O interruption follows the underlying transport's contract.
func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
		d.closeErr = d.transport.Close()
	})

	return d.closeErr
}

func (d *Device) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.closed:
		return io.ErrClosedPipe
	case d.mu <- struct{}{}:
	}

	if err := ctx.Err(); err != nil {
		d.unlock()
		return err
	}

	select {
	case <-d.closed:
		d.unlock()
		return io.ErrClosedPipe
	default:
	}

	return nil
}

func (d *Device) unlock() {
	<-d.mu
}

func (d *Device) operationError(err error) error {
	var invalidated *transport.DeviceInvalidatedError
	if errors.As(err, &invalidated) {
		return errors.Join(err, d.Close())
	}

	return err
}
