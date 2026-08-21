package policy

import "time"

// Limit7 密封策略限额。
type Limit7 struct {
	Name       string
	MaxPlain   int
	MaxAAD     int
	SealBudget time.Duration
}

func DefaultLimit7() Limit7 {
	return Limit7{
		Name:       "limit7",
		MaxPlain:   1024*1024 + 7,
		MaxAAD:     4096 + 7,
		SealBudget: time.Duration(7) * time.Millisecond,
	}
}

func (l Limit7) ClampPlain(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxPlain {
		return l.MaxPlain
	}
	return n
}

func (l Limit7) ClampAAD(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxAAD {
		return l.MaxAAD
	}
	return n
}

func (l Limit7) AllowSeal(plainLen int) bool {
	return plainLen <= l.MaxPlain
}

func MergeLimit7(a, b Limit7) Limit7 {
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
