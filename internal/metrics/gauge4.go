package metrics

import "sync"

type Gauge4 struct {
	mu       sync.Mutex
	sealed   int64
	opened   int64
	rotated  int64
	revoked  int64
	failed   int64
}

func NewGauge4() *Gauge4 { return &Gauge4{} }

func (g *Gauge4) IncSealed() { g.add(&g.sealed) }
func (g *Gauge4) IncOpened() { g.add(&g.opened) }
func (g *Gauge4) IncRotated() { g.add(&g.rotated) }
func (g *Gauge4) IncRevoked() { g.add(&g.revoked) }
func (g *Gauge4) IncFailed() { g.add(&g.failed) }

func (g *Gauge4) add(p *int64) { g.addN(p, 1) }

func (g *Gauge4) addN(p *int64, n int64) {
	g.mu.Lock()
	*p += n
	g.mu.Unlock()
}

func (g *Gauge4) Snapshot() map[string]int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return map[string]int64{
		"sealed": g.sealed, "opened": g.opened, "rotated": g.rotated,
		"revoked": g.revoked, "failed": g.failed,
	}
}
