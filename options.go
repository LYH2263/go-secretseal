package secretseal

import (
	"example.com/secretseal/internal/cipher"
	"example.com/secretseal/internal/policy"
)

type Options struct {
	Cipher      cipher.Factory
	PersistPath string
	Policy      policy.Policy
	LabelPrefix string
}

func (o *Options) normalize() {
	if o.Policy.MaxPlain == 0 {
		o.Policy = policy.Default()
	}
	if o.LabelPrefix == "" {
		o.LabelPrefix = "kek"
	}
}
