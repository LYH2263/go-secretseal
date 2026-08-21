package policy

import "time"

// Limit18 密封策略限额。
type Limit18 struct {
	Name       string
	MaxPlain   int
	MaxAAD     int
	SealBudget time.Duration
}

func DefaultLimit18() Limit18 {
	return Limit18{
		Name:       "limit18",
		MaxPlain:   1024*1024 + 18,
		MaxAAD:     4096 + 18,
		SealBudget: time.Duration(18) * time.Millisecond,
	}
}

func (l Limit18) ClampPlain(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxPlain {
		return l.MaxPlain
	}
	return n
}

func (l Limit18) ClampAAD(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxAAD {
		return l.MaxAAD
	}
	return n
}

func (l Limit18) AllowSeal(plainLen int) bool {
	return plainLen <= l.MaxPlain
}

func MergeLimit18(a, b Limit18) Limit18 {
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
