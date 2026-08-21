package secretseal

func (b *Box) ExportPublicMaterial(id string) (Material, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return Material{}, ErrClosed
	}
	e, ok := b.ring.Get(id)
	if !ok {
		return Material{}, wrapNotFound(id)
	}
	return Material{
		ID:    e.ID,
		Label: e.Label,
		Salt:  e.Salt,
		Meta:  e.Meta,
	}, nil
}
