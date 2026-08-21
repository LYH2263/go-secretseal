package secretseal

import (
	"crypto/rand"
	"time"

	"example.com/secretseal/internal/clone"
	"example.com/secretseal/internal/keyring"
)

func (b *Box) Add(id, label string, material []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrClosed
	}
	if id == "" || len(material) < 16 {
		return ErrInvalid
	}
	if label == "" {
		label = b.opts.LabelPrefix + "-" + id
	}
	mat := clone.Bytes(material)
	salt := make([]byte, 8)
	_, _ = rand.Read(salt)
	e := keyring.Entry{
		ID:        id,
		Label:     label,
		Material:  mat,
		Salt:      salt,
		Meta:      []string{"v1"},
		CreatedAt: time.Now().UTC(),
	}
	if err := b.ring.Add(e); err != nil {
		return ErrInvalid
	}
	// 仅当环内尚无 active 时才提升新密钥；落盘失败必须回滚这次提升，
	// 否则 active 会指向未持久化的密钥，内存与磁盘状态撕裂。
	setActive := b.ring.ActiveID() == ""
	if setActive {
		b.ring.SetActive(id)
	}
	if err := b.persistLocked(); err != nil {
		b.ring.Remove(id)
		return err
	}
	return nil
}

func (b *Box) ListKeys() []KeyView {
	b.mu.Lock()
	defer b.mu.Unlock()
	entries := b.ring.List()
	out := make([]KeyView, 0, len(entries))
	active := b.ring.ActiveID()
	for _, e := range entries {
		out = append(out, KeyView{
			ID: e.ID, Label: e.Label, CreatedAt: e.CreatedAt,
			Revoked: e.Revoked, Active: e.ID == active,
		})
	}
	return out
}

func (b *Box) ActiveKid() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ring.ActiveID()
}

func (b *Box) Stats() map[string]int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.metrics.Snapshot()
	s["keys"] = int64(b.ring.Len())
	return s
}
