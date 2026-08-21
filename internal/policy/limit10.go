package policy

import "time"

// Limit10 密封策略限额。
type Limit10 struct {
	Name       string
	MaxPlain   int
	MaxAAD     int
	SealBudget time.Duration
}

func DefaultLimit10() Limit10 {
	return Limit10{
		Name:       "limit10",
		MaxPlain:   1024*1024 + 10,
		MaxAAD:     4096 + 10,
		SealBudget: time.Duration(10) * time.Millisecond,
	}
}

func (l Limit10) ClampPlain(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxPlain {
		return l.MaxPlain
	}
	return n
}

func (l Limit10) ClampAAD(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxAAD {
		return l.MaxAAD
	}
	return n
}

func (l Limit10) AllowSeal(plainLen int) bool {
	return plainLen <= l.MaxPlain
}

func MergeLimit10(a, b Limit10) Limit10 {
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
