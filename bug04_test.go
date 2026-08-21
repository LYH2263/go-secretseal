package secretseal_test

import (
	"errors"
	"testing"

	"example.com/secretseal"
)

func TestBug04_NilCipherNoPanic(t *testing.T) {
	box, err := secretseal.New(secretseal.Options{Cipher: nil})
	if err != nil {
		t.Fatal(err)
	}
	defer box.Close()
	_ = box.Add("k4", "a", []byte("0123456789abcdef0123456789abcdef"))
	_, err = box.Seal([]byte("a"), []byte("p"))
	if !errors.Is(err, secretseal.ErrNoCipher) {
		t.Fatalf("got %v", err)
	}
}
