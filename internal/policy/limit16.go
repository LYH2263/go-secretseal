package policy

import "time"

// Limit16 密封策略限额。
type Limit16 struct {
	Name       string
	MaxPlain   int
	MaxAAD     int
	SealBudget time.Duration
}

func DefaultLimit16() Limit16 {
	return Limit16{
		Name:       "limit16",
		MaxPlain:   1024*1024 + 16,
		MaxAAD:     4096 + 16,
		SealBudget: time.Duration(16) * time.Millisecond,
	}
}

func (l Limit16) ClampPlain(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxPlain {
		return l.MaxPlain
	}
	return n
}

func (l Limit16) ClampAAD(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxAAD {
		return l.MaxAAD
	}
	return n
}

func (l Limit16) AllowSeal(plainLen int) bool {
	return plainLen <= l.MaxPlain
}

func MergeLimit16(a, b Limit16) Limit16 {
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
