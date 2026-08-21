package secretseal_test

import (
	"context"
	"errors"
	"testing"

	"example.com/secretseal"
	"example.com/secretseal/internal/cipher"
)

func TestBug07_SealContextHonorsCancel(t *testing.T) {
	box, err := secretseal.New(secretseal.Options{Cipher: cipher.NewAESGCM()})
	if err != nil {
		t.Fatal(err)
	}
	defer box.Close()
	_ = box.Add("k7", "a", []byte("0123456789abcdef0123456789abcdef"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = box.SealContext(ctx, []byte("a"), []byte("p"))
	if err == nil || (!errors.Is(err, secretseal.ErrCanceled) && !errors.Is(err, context.Canceled)) {
		t.Fatalf("got %v", err)
	}
}
