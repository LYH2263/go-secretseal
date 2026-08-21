package secretseal_test

import (
	"errors"
	"testing"

	"example.com/secretseal"
	"example.com/secretseal/internal/cipher"
)

func TestBug05_RevokeErrorWrapsSentinel(t *testing.T) {
	box, err := secretseal.New(secretseal.Options{Cipher: cipher.NewAESGCM()})
	if err != nil {
		t.Fatal(err)
	}
	defer box.Close()
	err = box.Revoke("missing")
	if !errors.Is(err, secretseal.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}
