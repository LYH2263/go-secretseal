package secretseal_test

import (
	"os"
	"path/filepath"
	"testing"

	"example.com/secretseal"
	"example.com/secretseal/internal/cipher"
)

func TestBug06_RotatePersistFailureKeepsActive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ring.json")
	box, err := secretseal.New(secretseal.Options{
		Cipher: cipher.NewAESGCM(), PersistPath: path,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer box.Close()
	if err := box.Add("old", "a", []byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	if box.ActiveKid() != "old" {
		t.Fatalf("active=%s", box.ActiveKid())
	}
	// 破坏路径：换成目录，后续 Save 失败
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	err = box.Rotate("new", "b", []byte("fedcba9876543210fedcba9876543210"))
	if err == nil {
		t.Fatal("expected persist error")
	}
	if box.ActiveKid() != "old" {
		t.Fatalf("active switched on persist fail: %s", box.ActiveKid())
	}
}
