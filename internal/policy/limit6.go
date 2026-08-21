package policy

import "time"

// Limit6 密封策略限额。
type Limit6 struct {
	Name       string
	MaxPlain   int
	MaxAAD     int
	SealBudget time.Duration
}

func DefaultLimit6() Limit6 {
	return Limit6{
		Name:       "limit6",
		MaxPlain:   1024*1024 + 6,
		MaxAAD:     4096 + 6,
		SealBudget: time.Duration(6) * time.Millisecond,
	}
}

func (l Limit6) ClampPlain(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxPlain {
		return l.MaxPlain
	}
	return n
}

func (l Limit6) ClampAAD(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxAAD {
		return l.MaxAAD
	}
	return n
}

func (l Limit6) AllowSeal(plainLen int) bool {
	return plainLen <= l.MaxPlain
}

func MergeLimit6(a, b Limit6) Limit6 {
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
