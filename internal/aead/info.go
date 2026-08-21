package aead

// Info 描述 AEAD 参数（文档/管理页展示）。
type Info struct {
	Name       string
	KeyBytes   int
	NonceBytes int
	TagBytes   int
}

func AES256GCM() Info {
	return Info{Name: "AES-256-GCM", KeyBytes: 32, NonceBytes: 12, TagBytes: 16}
}

func (i Info) String() string {
	return i.Name
}
