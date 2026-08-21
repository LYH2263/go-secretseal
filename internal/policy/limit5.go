package policy

import "time"

// Limit5 密封策略限额。
type Limit5 struct {
	Name       string
	MaxPlain   int
	MaxAAD     int
	SealBudget time.Duration
}

func DefaultLimit5() Limit5 {
	return Limit5{
		Name:       "limit5",
		MaxPlain:   1024*1024 + 5,
		MaxAAD:     4096 + 5,
		SealBudget: time.Duration(5) * time.Millisecond,
	}
}

func (l Limit5) ClampPlain(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxPlain {
		return l.MaxPlain
	}
	return n
}

func (l Limit5) ClampAAD(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxAAD {
		return l.MaxAAD
	}
	return n
}

func (l Limit5) AllowSeal(plainLen int) bool {
	return plainLen <= l.MaxPlain
}

func MergeLimit5(a, b Limit5) Limit5 {
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
