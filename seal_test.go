package secretseal

import (
	"errors"
	"testing"
)

// TestSealNilCipher 确保 New Box 时未配置 Cipher（nil），
// Seal 不应空指针 panic，而应返回约定的 ErrNoCipher。
func TestSealNilCipher(t *testing.T) {
	b, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// 不配置任何 cipher；plain 非空以越过 ErrInvalid 分支。
	_, err = b.Seal(nil, []byte("secret"))
	if !errors.Is(err, ErrNoCipher) {
		t.Fatalf("Seal with nil cipher: want ErrNoCipher, got %v", err)
	}
}

// TestOpenNilCipher 对称覆盖 Open 路径（同样不应 panic）。
func TestOpenNilCipher(t *testing.T) {
	b, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = b.Open(Blob{Kid: "k1", CT: []byte("x")})
	if !errors.Is(err, ErrNoCipher) {
		t.Fatalf("Open with nil cipher: want ErrNoCipher, got %v", err)
	}
}
