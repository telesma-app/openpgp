package client

import (
	"context"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
	"github.com/telesma-app/openpgp/transport"
)

// Client borrows an APDU transport without closing it.
type Client struct {
	transport      transport.APDU
	encoding       iso7816.Encoding
	emptyPutDataLe bool
}

// Option configures a Client before its first command.
type Option func(*Client)

// WithExtendedLength uses extended APDUs; SELECT and empty PUT DATA stay short.
// The card and reader must support extended length and the command's size.
// Support is not negotiated and rejected commands are not retried.
func WithExtendedLength() Option {
	return func(c *Client) {
		c.encoding = iso7816.EncodingExtended
	}
}

// WithEmptyPutDataLe adds short Le=256 to empty PUT DATA commands, including
// with WithExtendedLength. This compatibility form works around Token2 Smart
// Reader storing unrelated data for a four-byte empty PUT DATA (see TESTING.md).
// By default PUT DATA omits Le as specified in Sec. 7.2.8. The option does not
// affect nonempty writes. Commands are never retried.
// For SM key deletion with this option, use the nonempty F4 container D1 00 D2 00;
// deletion requires a status-only response without a logical Le (Sec. 7.5).
func WithEmptyPutDataLe() Option {
	return func(c *Client) {
		c.emptyPutDataLe = true
	}
}

// NewClient borrows transport without I/O, preserving its selection state.
// Commands use short APDUs with chaining by default. The caller establishes
// each command's required card state.
func NewClient(transport transport.APDU, options ...Option) *Client {
	c := &Client{transport: transport, encoding: iso7816.EncodingShort}
	for _, option := range options {
		option(c)
	}

	return c
}

func (c *Client) responseLength() uint32 {
	if c.encoding == iso7816.EncodingExtended {
		return 65536
	}

	return 256
}

func (c *Client) exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	response, err := c.transport.Exchange(ctx, command)
	if err != nil {
		return iso7816.Response{}, err
	}

	if err := response.APDUError(); err != nil {
		return iso7816.Response{}, err
	}

	return response, nil
}

func emptyResponse(response iso7816.Response) error {
	if len(response.Data) != 0 {
		return protocol.ErrInvalidResponse
	}

	return nil
}
