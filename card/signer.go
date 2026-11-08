package card

import (
	"context"
	"crypto"
	"io"
)

type signer struct {
	key            *PrivateKey
	ctx            context.Context
	authentication AuthenticationSource
}

var _ crypto.Signer = (*signer)(nil)

// Signer adapts the borrowed key and Device to crypto.Signer with ctx for the
// request's lifetime. The card supplies entropy; Sign's io.Reader is unused.
func (key *PrivateKey) Signer(ctx context.Context, authentication AuthenticationSource) crypto.Signer {
	return &signer{key: key, ctx: ctx, authentication: authentication}
}

func (s *signer) Public() crypto.PublicKey {
	return s.key.Public()
}

func (s *signer) Sign(_ io.Reader, input []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(s.ctx, input, opts, s.authentication)
}
