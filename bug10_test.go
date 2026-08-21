package secretseal_test

import (
	"path/filepath"
	"testing"

	"example.com/secretseal"
	"example.com/secretseal/internal/cipher"
)

func TestBug10_CloseFlushesBeforeClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ring.json")
	box, err := secretseal.New(secretseal.Options{Cipher: cipher.NewAESGCM(), PersistPath: path})
	if err != nil {
		t.Fatal(err)
	}
	box.StartBackground()
	if err := box.Add("keep", "a", []byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	if err := box.Close(); err != nil {
		t.Fatal(err)
	}
	box2, err := secretseal.New(secretseal.Options{Cipher: cipher.NewAESGCM(), PersistPath: path})
	if err != nil {
		t.Fatal(err)
	}
	defer box2.Close()
	if err := box2.LoadPersist(); err != nil {
		t.Fatal(err)
	}
	if len(box2.ListKeys()) < 1 {
		t.Fatal("Close flushed empty keyring")
	}
}
