package secretseal

import (
	"context"
	"time"

	"example.com/secretseal/internal/clone"
	"example.com/secretseal/internal/dek"
	"example.com/secretseal/internal/wait"
)

func (b *Box) Open(bl Blob) ([]byte, error) {
	return b.OpenContext(context.Background(), bl)
}

func (b *Box) OpenContext(ctx context.Context, bl Blob) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, wrapCancel(err)
	}
	if err := b.pol.WaitOpen(ctx); err != nil {
		return nil, wrapCancel(err)
	}
	// 可选短等待（测试可取消）
	if err := wait.Context(ctx, time.Millisecond); err != nil {
		return nil, wrapCancel(err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, ErrClosed
	}
	if b.fac == nil {
		return nil, ErrNoCipher
	}
	e, ok := b.ring.Get(bl.Kid)
	if !ok {
		return nil, wrapNotFound(bl.Kid)
	}
	if e.Revoked {
		return nil, ErrRevoked
	}
	rawDEK, err := dek.Unwrap(e.Material, bl.Wrap)
	if err != nil {
		return nil, wrapOpen(err)
	}
	plain, err := b.fac.Open(rawDEK, bl.Nonce, bl.AAD, bl.CT)
	if err != nil {
		return nil, wrapOpen(err)
	}
	b.metrics.IncOpened()
	return clone.Bytes(plain), nil
}
