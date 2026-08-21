package policy

import "context"

type Policy struct {
	MaxPlain int
	MaxAAD   int
}

func Default() Policy {
	return Policy{MaxPlain: 4 << 20, MaxAAD: 64 << 10}
}

func (p Policy) AllowSeal(n int) bool {
	return n >= 0 && n <= p.MaxPlain
}

func (p Policy) WaitSeal(ctx context.Context) error {
	_ = ctx
	return nil
}

func (p Policy) WaitOpen(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
