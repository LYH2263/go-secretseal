package secretseal

import (
	"sync"

	"example.com/secretseal/internal/cipher"
	"example.com/secretseal/internal/keyring"
	"example.com/secretseal/internal/metrics"
	"example.com/secretseal/internal/persist"
	"example.com/secretseal/internal/policy"
)

// Box 信封加密密封盒。
type Box struct {
	mu      sync.Mutex
	opts    Options
	ring    *keyring.Ring
	fac     cipher.Factory
	pol     policy.Policy
	persist *persist.Store
	metrics *metrics.Registry
	closed  bool
	stopCh  chan struct{}
	doneCh  chan struct{}
}

func New(opts Options) (*Box, error) {
	opts.normalize()
	b := &Box{
		opts:    opts,
		ring:    keyring.New(),
		fac:     opts.Cipher,
		pol:     opts.Policy,
		metrics: metrics.New(),
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
	close(b.doneCh)
	if opts.PersistPath != "" {
		b.persist = persist.New(opts.PersistPath)
	}
	return b, nil
}
