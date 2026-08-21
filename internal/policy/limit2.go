package policy

import "time"

// Limit2 密封策略限额。
type Limit2 struct {
	Name       string
	MaxPlain   int
	MaxAAD     int
	SealBudget time.Duration
}

func DefaultLimit2() Limit2 {
	return Limit2{
		Name:       "limit2",
		MaxPlain:   1024*1024 + 2,
		MaxAAD:     4096 + 2,
		SealBudget: time.Duration(2) * time.Millisecond,
	}
}

func (l Limit2) ClampPlain(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxPlain {
		return l.MaxPlain
	}
	return n
}

func (l Limit2) ClampAAD(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxAAD {
		return l.MaxAAD
	}
	return n
}

func (l Limit2) AllowSeal(plainLen int) bool {
	return plainLen <= l.MaxPlain
}

func MergeLimit2(a, b Limit2) Limit2 {
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
