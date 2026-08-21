package policy

import "time"

// Limit13 密封策略限额。
type Limit13 struct {
	Name       string
	MaxPlain   int
	MaxAAD     int
	SealBudget time.Duration
}

func DefaultLimit13() Limit13 {
	return Limit13{
		Name:       "limit13",
		MaxPlain:   1024*1024 + 13,
		MaxAAD:     4096 + 13,
		SealBudget: time.Duration(13) * time.Millisecond,
	}
}

func (l Limit13) ClampPlain(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxPlain {
		return l.MaxPlain
	}
	return n
}

func (l Limit13) ClampAAD(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxAAD {
		return l.MaxAAD
	}
	return n
}

func (l Limit13) AllowSeal(plainLen int) bool {
	return plainLen <= l.MaxPlain
}

func MergeLimit13(a, b Limit13) Limit13 {
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
