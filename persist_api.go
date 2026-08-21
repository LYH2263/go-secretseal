package secretseal

import (
	"example.com/secretseal/internal/keyring"
	"example.com/secretseal/internal/persist"
)

func (b *Box) persistLocked() error {
	if b.persist == nil {
		return nil
	}
	// ring 为空时绝不落盘空快照——会覆盖 ring.json 导致密钥全丢。
	// Close 应先刷盘再清 keyring，正常路径不会到这里；到这说明调用顺序有误，跳过更安全。
	if b.ring == nil {
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
