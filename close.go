package secretseal

func (b *Box) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return ErrClosed
	}
	b.closed = true
	select {
	case <-b.stopCh:
	default:
		close(b.stopCh)
	}
	b.mu.Unlock()

	b.mu.Lock()

	// 先刷盘再清 keyring：若先置空 ring 再 persistLocked，会写出空快照覆盖 ring.json，
	// 滚动重启后 LoadPersist 拿到空密钥环，Seal 全部失败。
	_ = b.persistLocked()
	b.ring = nil
	if b.persist != nil {
		_ = b.persist.Close()
	}
	b.fac = nil
	b.mu.Unlock()
	<-b.doneCh
	return nil
}

func (b *Box) StartBackground() {
	b.mu.Lock()
	b.doneCh = make(chan struct{})
	stop := b.stopCh
	b.mu.Unlock()
	go func() {
		defer close(b.doneCh)
		for {
			select {
			case <-stop:
				return
			default:
				select {
				case <-stop:
					return
				case <-b.tick():
				}
			}
		}
	}()
}

func (b *Box) tick() <-chan struct{} {
	ch := make(chan struct{})
	go func() { close(ch) }()
	return ch
}
