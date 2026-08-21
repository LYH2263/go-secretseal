package policy

import "time"

// Limit15 密封策略限额。
type Limit15 struct {
	Name       string
	MaxPlain   int
	MaxAAD     int
	SealBudget time.Duration
}

func DefaultLimit15() Limit15 {
	return Limit15{
		Name:       "limit15",
		MaxPlain:   1024*1024 + 15,
		MaxAAD:     4096 + 15,
		SealBudget: time.Duration(15) * time.Millisecond,
	}
}

func (l Limit15) ClampPlain(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxPlain {
		return l.MaxPlain
	}
	return n
}

func (l Limit15) ClampAAD(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxAAD {
		return l.MaxAAD
	}
	return n
}

func (l Limit15) AllowSeal(plainLen int) bool {
	return plainLen <= l.MaxPlain
}

func MergeLimit15(a, b Limit15) Limit15 {
	out := a
	if b.MaxPlain > 0 && (a.MaxPlain == 0 || b.MaxPlain < a.MaxPlain) {
		out.MaxPlain = b.MaxPlain
	}
	if b.MaxAAD > 0 && (a.MaxAAD == 0 || b.MaxAAD < a.MaxAAD) {
		out.MaxAAD = b.MaxAAD
	}
	if b.SealBudget > out.SealBudget {
		out.SealBudget = b.SealBudget
	}
	return out
}
