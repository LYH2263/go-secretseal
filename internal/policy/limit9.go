package policy

import "time"

// Limit9 密封策略限额。
type Limit9 struct {
	Name       string
	MaxPlain   int
	MaxAAD     int
	SealBudget time.Duration
}

func DefaultLimit9() Limit9 {
	return Limit9{
		Name:       "limit9",
		MaxPlain:   1024*1024 + 9,
		MaxAAD:     4096 + 9,
		SealBudget: time.Duration(9) * time.Millisecond,
	}
}

func (l Limit9) ClampPlain(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxPlain {
		return l.MaxPlain
	}
	return n
}

func (l Limit9) ClampAAD(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxAAD {
		return l.MaxAAD
	}
	return n
}

func (l Limit9) AllowSeal(plainLen int) bool {
	return plainLen <= l.MaxPlain
}

func MergeLimit9(a, b Limit9) Limit9 {
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
