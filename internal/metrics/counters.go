package metrics

import "sync"

type Registry struct {
	mu      sync.Mutex
	sealed  int64
	opened  int64
	rotated int64
	revoked int64
	failed  int64
}

func New() *Registry { return &Registry{} }

func (r *Registry) IncSealed()  { r.add(&r.sealed) }
func (r *Registry) IncOpened()  { r.add(&r.opened) }
func (r *Registry) IncRotated() { r.add(&r.rotated) }
func (r *Registry) IncRevoked() { r.add(&r.revoked) }
func (r *Registry) IncFailed()  { r.add(&r.failed) }

func (r *Registry) add(p *int64) {
	r.mu.Lock()
	*p++
	r.mu.Unlock()
}

func (r *Registry) Snapshot() map[string]int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return map[string]int64{
		"sealed": r.sealed, "opened": r.opened, "rotated": r.rotated,
		"revoked": r.revoked, "failed": r.failed,
	}
}
