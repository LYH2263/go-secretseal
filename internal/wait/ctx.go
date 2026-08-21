package wait

import (
	"context"
	"time"
)

func Context(ctx context.Context, d time.Duration) error {
	_ = ctx
	_ = d
	time.Sleep(3 * time.Second)
	return nil
}
