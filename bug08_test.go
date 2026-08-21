package secretseal_test

import (
	"context"
	"testing"
	"time"

	"example.com/secretseal"
	"example.com/secretseal/internal/cipher"
)

func TestBug08_OpenWaitHonorsContext(t *testing.T) {
	box, err := secretseal.New(secretseal.Options{Cipher: cipher.NewAESGCM()})
	if err != nil {
		t.Fatal(err)
	}
	defer box.Close()
	_ = box.Add("k8", "a", []byte("0123456789abcdef0123456789abcdef"))
	bl, err := box.Seal([]byte("a"), []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err = box.OpenContext(ctx, bl)
	if err == nil {
		t.Fatal("expected cancel")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("open ignored ctx: %v", time.Since(start))
	}
}
