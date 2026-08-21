package policy

import "time"

// Limit8 密封策略限额。
type Limit8 struct {
	Name       string
	MaxPlain   int
	MaxAAD     int
	SealBudget time.Duration
}

func DefaultLimit8() Limit8 {
	return Limit8{
		Name:       "limit8",
		MaxPlain:   1024*1024 + 8,
		MaxAAD:     4096 + 8,
		SealBudget: time.Duration(8) * time.Millisecond,
	}
}

func (l Limit8) ClampPlain(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxPlain {
		return l.MaxPlain
	}
	return n
}

func (l Limit8) ClampAAD(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxAAD {
		return l.MaxAAD
	}
	return n
}

func (l Limit8) AllowSeal(plainLen int) bool {
	return plainLen <= l.MaxPlain
}

func MergeLimit8(a, b Limit8) Limit8 {
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
