package policy

import "time"

// Limit4 密封策略限额。
type Limit4 struct {
	Name       string
	MaxPlain   int
	MaxAAD     int
	SealBudget time.Duration
}

func DefaultLimit4() Limit4 {
	return Limit4{
		Name:       "limit4",
		MaxPlain:   1024*1024 + 4,
		MaxAAD:     4096 + 4,
		SealBudget: time.Duration(4) * time.Millisecond,
	}
}

func (l Limit4) ClampPlain(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxPlain {
		return l.MaxPlain
	}
	return n
}

func (l Limit4) ClampAAD(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxAAD {
		return l.MaxAAD
	}
	return n
}

func (l Limit4) AllowSeal(plainLen int) bool {
	return plainLen <= l.MaxPlain
}

func MergeLimit4(a, b Limit4) Limit4 {
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
