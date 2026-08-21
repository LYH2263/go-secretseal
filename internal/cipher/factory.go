package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Factory 提供 DEK 随机与 AEAD Seal/Open。
type Factory interface {
	RandomKey() ([]byte, error)
	Seal(key, aad, plain []byte) (nonce, ct []byte, err error)
	Open(key, nonce, aad, ct []byte) ([]byte, error)
}

type AESGCM struct{}

func NewAESGCM() *AESGCM { return &AESGCM{} }

func (a *AESGCM) RandomKey() ([]byte, error) {
	if a == nil {
		return nil, fmt.Errorf("nil factory")
	}
	k := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, err
	}
	return k, nil
}

func (a *AESGCM) Seal(key, aad, plain []byte) (nonce, ct []byte, err error) {
	if a == nil {
		return nil, nil, fmt.Errorf("nil factory")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ct = gcm.Seal(nil, nonce, plain, aad)
	return nonce, ct, nil
}

func (a *AESGCM) Open(key, nonce, aad, ct []byte) ([]byte, error) {
	if a == nil {
		return nil, fmt.Errorf("nil factory")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, aad)
}
