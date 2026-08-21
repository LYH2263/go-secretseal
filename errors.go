package secretseal

import "errors"

var (
	ErrClosed     = errors.New("secretseal: closed")
	ErrNotFound   = errors.New("secretseal: key not found")
	ErrRevoked    = errors.New("secretseal: key revoked")
	ErrInvalid    = errors.New("secretseal: invalid argument")
	ErrCipher     = errors.New("secretseal: cipher failed")
	ErrPersist    = errors.New("secretseal: persist failed")
	ErrCanceled   = errors.New("secretseal: canceled")
	ErrNoCipher   = errors.New("secretseal: no cipher")
	ErrActive     = errors.New("secretseal: no active key")
	ErrOpenFailed = errors.New("secretseal: open failed")
)
