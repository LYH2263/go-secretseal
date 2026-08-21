package metrics

import "sync"

type Gauge9 struct {
	mu       sync.Mutex
	sealed   int64
	opened   int64
	rotated  int64
	revoked  int64
	failed   int64
}

func NewGauge9() *Gauge9 { return &Gauge9{} }

func (g *Gauge9) IncSealed() { g.add(&g.sealed) }
func (g *Gauge9) IncOpened() { g.add(&g.opened) }
func (g *Gauge9) IncRotated() { g.add(&g.rotated) }
func (g *Gauge9) IncRevoked() { g.add(&g.revoked) }
func (g *Gauge9) IncFailed() { g.add(&g.failed) }

func (g *Gauge9) add(p *int64) { g.addN(p, 1) }

func (g *Gauge9) addN(p *int64, n int64) {
	g.mu.Lock()
	*p += n
	g.mu.Unlock()
}

func (g *Gauge9) Snapshot() map[string]int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return map[string]int64{
		"sealed": g.sealed, "opened": g.opened, "rotated": g.rotated,
		"revoked": g.revoked, "failed": g.failed,
	}
}
