// SELECT and selection during connection setup (Sec. 7.2.1).
package iso7816

import (
	"context"
	"fmt"

	baseiso7816 "github.com/telesma-app/iso7816"
	"github.com/telesma-app/openpgp/protocol"
)

// Select selects OpenPGP and ignores optional FCI. It borrows card without
// closing it, including on failure. Status 6285 (awaiting activation) returns
// an APDUError; Open accepts it for recovery with ACTIVATE FILE.
func Select(ctx context.Context, card baseiso7816.Card, options ...Option) error {
	response, err := Exchange(ctx, card, protocol.SelectCommand(), options...)
	if err != nil {
		return fmt.Errorf("iso7816: select OpenPGP application: %w", err)
	}

	if err := response.APDUError(); err != nil {
		return fmt.Errorf("iso7816: select OpenPGP application: %w", err)
	}

	return nil
}

// Open selects OpenPGP and takes ownership of card on success. On failure,
// including invalidation, the caller retains ownership. SELECT status 6285
// is accepted; the application then requires ActivateFile before use.
func Open(ctx context.Context, card Card, options ...Option) (*Transport, error) {
	parameters := commandParameters(options)

	response, err := exchangeCommand(ctx, card, protocol.SelectCommand(), parameters)
	if err != nil {
		return nil, fmt.Errorf("iso7816: select OpenPGP application: %w", err)
	}
	// A terminated application is selected but needs ACTIVATE FILE (Sec. 7.2.16).
	if response.Status != 0x6285 {
		if err := response.APDUError(); err != nil {
			return nil, fmt.Errorf("iso7816: select OpenPGP application: %w", err)
		}
	}

	return newTransportWithParameters(card, parameters), nil
}
