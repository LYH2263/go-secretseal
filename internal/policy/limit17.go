package policy

import "time"

// Limit17 密封策略限额。
type Limit17 struct {
	Name       string
	MaxPlain   int
	MaxAAD     int
	SealBudget time.Duration
}

func DefaultLimit17() Limit17 {
	return Limit17{
		Name:       "limit17",
		MaxPlain:   1024*1024 + 17,
		MaxAAD:     4096 + 17,
		SealBudget: time.Duration(17) * time.Millisecond,
	}
}

func (l Limit17) ClampPlain(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxPlain {
		return l.MaxPlain
	}
	return n
}

func (l Limit17) ClampAAD(n int) int {
	if n < 0 {
		return 0
	}
	if n > l.MaxAAD {
		return l.MaxAAD
	}
	return n
}

func (l Limit17) AllowSeal(plainLen int) bool {
	return plainLen <= l.MaxPlain
}

func MergeLimit17(a, b Limit17) Limit17 {
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
