package secretseal

import (
	"example.com/secretseal/internal/keyring"
	"example.com/secretseal/internal/persist"
)

func (b *Box) persistLocked() error {
	if b.persist == nil {
		return nil
	}
	entries := b.ring.List()
	snap := persist.Snapshot{
		Active:  b.ring.ActiveID(),
		Entries: append([]keyring.Entry(nil), entries...),
	}
	if err := b.persist.Save(snap); err != nil {
		return wrapPersist(err)
	}
	// Close 须释放 Save 打开的句柄
	return nil
}

func (b *Box) LoadPersist() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.persist == nil {
		return nil
	}
	snap, err := b.persist.Load()
	if err != nil {
		return wrapPersist(err)
	}
	b.ring = keyring.New()
	for _, e := range snap.Entries {
		_ = b.ring.Add(e)
	}
	if snap.Active != "" {
		b.ring.SetActive(snap.Active)
	}
	return nil
}
