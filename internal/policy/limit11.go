package policy

import "time"

// Limit11 密封策略限额。
type Limit11 struct {
	Name       string
	MaxPlain   int
	MaxAAD     int
	SealBudget time.Duration
}

func DefaultLimit11() Limit11 {
	return Limit11{
		Name:       "limit11",
		MaxPlain:   1024*1024 + 11,
		MaxAAD:     4096 + 11,
		SealBudget: time.Duration(11) * time.Millisecond,
	}
}

func (l Limit11) ClampPlain(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxPlain {
		return l.MaxPlain
	}
	return n
}

func (l Limit11) ClampAAD(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxAAD {
		return l.MaxAAD
	}
	return n
}

func (l Limit11) AllowSeal(plainLen int) bool {
	return plainLen <= l.MaxPlain
}

func MergeLimit11(a, b Limit11) Limit11 {
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
