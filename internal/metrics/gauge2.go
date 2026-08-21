package metrics

import "sync"

type Gauge2 struct {
	mu       sync.Mutex
	sealed   int64
	opened   int64
	rotated  int64
	revoked  int64
	failed   int64
}

func NewGauge2() *Gauge2 { return &Gauge2{} }

func (g *Gauge2) IncSealed() { g.add(&g.sealed) }
func (g *Gauge2) IncOpened() { g.add(&g.opened) }
func (g *Gauge2) IncRotated() { g.add(&g.rotated) }
func (g *Gauge2) IncRevoked() { g.add(&g.revoked) }
func (g *Gauge2) IncFailed() { g.add(&g.failed) }

func (g *Gauge2) add(p *int64) { g.addN(p, 1) }

func (g *Gauge2) addN(p *int64, n int64) {
	g.mu.Lock()
	*p += n
	g.mu.Unlock()
}

func (g *Gauge2) Snapshot() map[string]int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return map[string]int64{
		"sealed": g.sealed, "opened": g.opened, "rotated": g.rotated,
		"revoked": g.revoked, "failed": g.failed,
	}
}
