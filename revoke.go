package secretseal

func (b *Box) Revoke(id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrClosed
	}
	if id == "" {
		return ErrInvalid
	}
	e, ok := b.ring.Get(id)
	if !ok {
		return wrapNotFound(id)
	}
	// 记下撤销前的状态，落盘失败时原样回滚，避免撤销生效在内存
	// 却未落盘：重启后该密钥复活、甚至 active 仍指向已撤销密钥。
	wasActive := b.ring.ActiveID() == id
	prev := e
	prev.Revoked = false
	e.Revoked = true
	b.ring.Put(e)
	if wasActive {
		b.ring.SetActive("")
	}
	if err := b.persistLocked(); err != nil {
		b.ring.Put(prev)
		if wasActive {
			b.ring.SetActive(id)
		}
		return err
	}
	b.metrics.IncRevoked()
	return nil
}
