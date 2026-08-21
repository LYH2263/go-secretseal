package policy

import "time"

// Limit1 密封策略限额。
type Limit1 struct {
	Name       string
	MaxPlain   int
	MaxAAD     int
	SealBudget time.Duration
}

func DefaultLimit1() Limit1 {
	return Limit1{
		Name:       "limit1",
		MaxPlain:   1024*1024 + 1,
		MaxAAD:     4096 + 1,
		SealBudget: time.Duration(1) * time.Millisecond,
	}
}

func (l Limit1) ClampPlain(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxPlain {
		return l.MaxPlain
	}
	return n
}

func (l Limit1) ClampAAD(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxAAD {
		return l.MaxAAD
	}
	return n
}

func (l Limit1) AllowSeal(plainLen int) bool {
	return plainLen <= l.MaxPlain
}

func MergeLimit1(a, b Limit1) Limit1 {
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
