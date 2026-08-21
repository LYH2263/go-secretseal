package policy

import "time"

// Limit3 密封策略限额。
type Limit3 struct {
	Name       string
	MaxPlain   int
	MaxAAD     int
	SealBudget time.Duration
}

func DefaultLimit3() Limit3 {
	return Limit3{
		Name:       "limit3",
		MaxPlain:   1024*1024 + 3,
		MaxAAD:     4096 + 3,
		SealBudget: time.Duration(3) * time.Millisecond,
	}
}

func (l Limit3) ClampPlain(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxPlain {
		return l.MaxPlain
	}
	return n
}

func (l Limit3) ClampAAD(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxAAD {
		return l.MaxAAD
	}
	return n
}

func (l Limit3) AllowSeal(plainLen int) bool {
	return plainLen <= l.MaxPlain
}

func MergeLimit3(a, b Limit3) Limit3 {
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
