package secretseal_test

import (
	"os"
	"path/filepath"
	"testing"

	"example.com/secretseal"
	"example.com/secretseal/internal/cipher"
)

func TestBug09_PersistFileClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ring.json")
	box, err := secretseal.New(secretseal.Options{Cipher: cipher.NewAESGCM(), PersistPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := box.Add("k9", "a", []byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	if err := box.Close(); err != nil {
		t.Fatal(err)
	}
	rotated := path + ".1"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatalf("rename after Close: %v", err)
	}
}
