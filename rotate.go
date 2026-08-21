package secretseal

import (
	"context"
	"crypto/rand"
	"time"

	"example.com/secretseal/internal/clone"
	"example.com/secretseal/internal/keyring"
)

func (b *Box) Rotate(newID, label string, material []byte) error {
	return b.RotateContext(context.Background(), newID, label, material)
}

func (b *Box) RotateContext(ctx context.Context, newID, label string, material []byte) error {
	if err := ctx.Err(); err != nil {
		return wrapCancel(err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrClosed
	}
	if newID == "" || len(material) < 16 {
		return ErrInvalid
	}
	mat := clone.Bytes(material)
	salt := make([]byte, 8)
	_, _ = rand.Read(salt)
	if label == "" {
		label = b.opts.LabelPrefix + "-" + newID
	}
	e := keyring.Entry{
		ID: newID, Label: label, Material: mat, Salt: salt,
		Meta: []string{"rotated"}, CreatedAt: time.Now().UTC(),
	}
	if err := b.ring.Add(e); err != nil {
		return ErrInvalid
	}
	b.ring.SetActive(newID)
	if err := b.persistLocked(); err != nil {

		return err
	}
	b.metrics.IncRotated()
	return nil
}
