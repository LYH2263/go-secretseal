package wait

import (
	"context"
	"time"
)

// Context blocks for at most d, returning early when ctx is canceled or its
// deadline expires. It returns the context's error on cancellation (so callers
// can surface a cancel-class error quickly) and nil once d elapses.
func Context(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
