package secretseal_test

import (
	"testing"

	"example.com/secretseal"
	"example.com/secretseal/internal/cipher"
)

func TestBug01_SealPlainSliceAlias(t *testing.T) {
	box, err := secretseal.New(secretseal.Options{Cipher: cipher.NewAESGCM()})
	if err != nil {
		t.Fatal(err)
	}
	defer box.Close()
	if err := box.Add("k1", "a", []byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	aad := []byte("AAD-KEEP")
	bl, err := box.Seal(aad, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	aad[0] = 'X'
	if string(bl.AAD) != "AAD-KEEP" {
		t.Fatalf("aad aliased in blob: %q", bl.AAD)
	}
	plain, err := box.Open(bl)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "hello" {
		t.Fatalf("open: %q", plain)
	}
}
