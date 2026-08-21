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
	e.Revoked = true
	b.ring.Put(e)
	if b.ring.ActiveID() == id {
		b.ring.SetActive("")
	}
	b.metrics.IncRevoked()
	return b.persistLocked()
}
