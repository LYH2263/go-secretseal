package wait

import (
	"context"
	"testing"
	"time"
)

// TestContext_ImmediateReturn ensures a zero duration returns at once. This
// guards against the old implementation that ignored d and slept a fixed 3s.
func TestContext_ImmediateReturn(t *testing.T) {
	start := time.Now()
	if err := Context(context.Background(), 0); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("Context(0) slept %v; should return immediately", elapsed)
	}
}

// TestContext_BlockedReturnsAfterDuration ensures a blocking call honors d
// instead of a hard-coded sleep.
func TestContext_BlockedReturnsAfterDuration(t *testing.T) {
	d := 40 * time.Millisecond
	start := time.Now()
	if err := Context(context.Background(), d); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < d {
		t.Fatalf("returned after %v, expected to block >= %v", elapsed, d)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("returned after %v, expected ~%v (no fixed 3s sleep)", elapsed, d)
	}
}

// TestContext_CanceledContextReturnsFast ensures cancellation interrupts the
// wait. This is the core of the reported bug: cancel must not wait out a
// fixed internal sleep.
func TestContext_CanceledContextReturnsFast(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err := Context(ctx, time.Second)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from canceled context, got nil")
	}
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if elapsed > 50*time.Millisecond {
		t.Fatalf("canceled Context returned after %v; should be near-instant", elapsed)
	}
}

// TestContext_DeadlineInterrupts ensures a deadline that fires during the
// wait returns DeadlineExceeded promptly.
func TestContext_DeadlineInterrupts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := Context(ctx, 5*time.Second)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from expired deadline, got nil")
	}
	if err != context.DeadlineExceeded {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("deadline Context returned after %v; should be near the 20ms deadline", elapsed)
	}
}
