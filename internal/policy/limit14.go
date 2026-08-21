package policy

import "time"

// Limit14 密封策略限额。
type Limit14 struct {
	Name       string
	MaxPlain   int
	MaxAAD     int
	SealBudget time.Duration
}

func DefaultLimit14() Limit14 {
	return Limit14{
		Name:       "limit14",
		MaxPlain:   1024*1024 + 14,
		MaxAAD:     4096 + 14,
		SealBudget: time.Duration(14) * time.Millisecond,
	}
}

func (l Limit14) ClampPlain(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxPlain {
		return l.MaxPlain
	}
	return n
}

func (l Limit14) ClampAAD(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxAAD {
		return l.MaxAAD
	}
	return n
}

func (l Limit14) AllowSeal(plainLen int) bool {
	return plainLen <= l.MaxPlain
}

func MergeLimit14(a, b Limit14) Limit14 {
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
