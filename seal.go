package secretseal

import (
	"context"

	"example.com/secretseal/internal/blob"
	"example.com/secretseal/internal/clone"
	"example.com/secretseal/internal/dek"
)

func (b *Box) Seal(aad, plain []byte) (Blob, error) {
	return b.SealContext(context.Background(), aad, plain)
}

func (b *Box) SealContext(ctx context.Context, aad, plain []byte) (Blob, error) {

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return Blob{}, ErrClosed
	}
	if b.fac == nil {
		return Blob{}, ErrNoCipher
	}
	if plain == nil {
		return Blob{}, ErrInvalid
	}
	if !b.pol.AllowSeal(len(plain)) {
		return Blob{}, ErrInvalid
	}
	active := b.ring.Active()
	if active == nil {
		return Blob{}, ErrActive
	}
	if active.Revoked {
		return Blob{}, ErrRevoked
	}
	plainCopy := clone.Bytes(plain)
	aadCopy := clone.Bytes(aad)
	rawDEK, err := b.fac.RandomKey()
	if err != nil {
		return Blob{}, wrapCipher(err)
	}
	nonce, ct, err := b.fac.Seal(rawDEK, aadCopy, plainCopy)
	if err != nil {
		return Blob{}, wrapCipher(err)
	}
	wrapped, err := dek.Wrap(active.Material, rawDEK)
	if err != nil {
		return Blob{}, wrapCipher(err)
	}
	out := Blob{
		Kid:   active.ID,
		Nonce: clone.Bytes(nonce),
		Wrap:  clone.Bytes(wrapped),
		CT:    clone.Bytes(ct),
		AAD:   clone.Bytes(aadCopy),
	}
	_ = blob.Encode(out.Kid, out.Nonce, out.Wrap, out.CT)
	b.metrics.IncSealed()
	return out, nil
}
