package card

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/telesma-app/iso7816"
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
