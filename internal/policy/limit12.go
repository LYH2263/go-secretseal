package policy

import "time"

// Limit12 密封策略限额。
type Limit12 struct {
	Name       string
	MaxPlain   int
	MaxAAD     int
	SealBudget time.Duration
}

func DefaultLimit12() Limit12 {
	return Limit12{
		Name:       "limit12",
		MaxPlain:   1024*1024 + 12,
		MaxAAD:     4096 + 12,
		SealBudget: time.Duration(12) * time.Millisecond,
	}
}

func (l Limit12) ClampPlain(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxPlain {
		return l.MaxPlain
	}
	return n
}

func (l Limit12) ClampAAD(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxAAD {
		return l.MaxAAD
	}
	return n
}

func (l Limit12) AllowSeal(plainLen int) bool {
	return plainLen <= l.MaxPlain
}

func MergeLimit12(a, b Limit12) Limit12 {
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
