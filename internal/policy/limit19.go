package policy

import "time"

// Limit19 密封策略限额。
type Limit19 struct {
	Name       string
	MaxPlain   int
	MaxAAD     int
	SealBudget time.Duration
}

func DefaultLimit19() Limit19 {
	return Limit19{
		Name:       "limit19",
		MaxPlain:   1024*1024 + 19,
		MaxAAD:     4096 + 19,
		SealBudget: time.Duration(19) * time.Millisecond,
	}
}

func (l Limit19) ClampPlain(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxPlain {
		return l.MaxPlain
	}
	return n
}

func (l Limit19) ClampAAD(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxAAD {
		return l.MaxAAD
	}
	return n
}

func (l Limit19) AllowSeal(plainLen int) bool {
	return plainLen <= l.MaxPlain
}

func MergeLimit19(a, b Limit19) Limit19 {
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
