package secretseal_test

import (
	"testing"

	"example.com/secretseal"
	"example.com/secretseal/internal/cipher"
)

func TestBug02_ExportMaterialSliceAlias(t *testing.T) {
	box, err := secretseal.New(secretseal.Options{Cipher: cipher.NewAESGCM()})
	if err != nil {
		t.Fatal(err)
	}
	defer box.Close()
	if err := box.Add("k2", "lab", []byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	m, err := box.ExportPublicMaterial("k2")
	if err != nil {
		t.Fatal(err)
	}
	orig := append([]byte(nil), m.Salt...)
	m.Salt[0] ^= 0xff
	if len(m.Meta) > 0 {
		m.Meta[0] = "mutated"
	}
	m2, err := box.ExportPublicMaterial("k2")
	if err != nil {
		t.Fatal(err)
	}
	if string(m2.Salt) != string(orig) {
		t.Fatalf("salt aliased: %v vs %v", m2.Salt, orig)
	}
	if len(m2.Meta) > 0 && m2.Meta[0] == "mutated" {
		t.Fatal("meta aliased")
	}
}
