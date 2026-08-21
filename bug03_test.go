package secretseal_test

import (
	"errors"
	"testing"

	"example.com/secretseal"
	"example.com/secretseal/internal/cipher"
)

func TestBug03_SealAfterCloseNoPanic(t *testing.T) {
	box, err := secretseal.New(secretseal.Options{Cipher: cipher.NewAESGCM()})
	if err != nil {
		t.Fatal(err)
	}
	_ = box.Add("k3", "a", []byte("0123456789abcdef0123456789abcdef"))
	_ = box.Close()
	_, err = box.Seal([]byte("a"), []byte("p"))
	if !errors.Is(err, secretseal.ErrClosed) {
		t.Fatalf("got %v", err)
	}
}
