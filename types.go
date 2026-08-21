package secretseal

import "time"

// KeyView 密钥环条目视图（不含私密材料）。
type KeyView struct {
	ID        string
	Label     string
	CreatedAt time.Time
	Revoked   bool
	Active    bool
}

// Material 导出的公开材料（标签/盐等），调用方改写不得污染环内状态。
type Material struct {
	ID    string
	Label string
	Salt  []byte
	Meta  []string
}

// SealSpec 密封入参。
type SealSpec struct {
	AAD   []byte
	Plain []byte
}

// Blob 密封输出。
type Blob struct {
	Kid   string
	Nonce []byte
	Wrap  []byte
	CT    []byte
	AAD   []byte
}
