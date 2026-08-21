package secretseal

import (
	"path/filepath"
	"testing"

	"example.com/secretseal/internal/cipher"
	"example.com/secretseal/internal/persist"
)

// newMisconfiguredBox 构造一个 PersistPath 指向已存在目录的 Box，
// 复现“有人把 PersistPath 误配成目录”：Save 在 os.Rename 时必然失败。
func newMisconfiguredBox(t *testing.T) *Box {
	t.Helper()
	dir := t.TempDir() // 已存在的目录
	b, err := New(Options{
		Cipher:      cipher.NewAESGCM(),
		PersistPath: dir, // 错配：PersistPath 指向目录而非文件
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func mustAdd(t *testing.T, b *Box, id string) {
	t.Helper()
	if err := b.Add(id, "", []byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatalf("Add %s: %v", id, err)
	}
}

func TestRotate_RollbackActiveOnPersistFailure(t *testing.T) {
	// 落盘失败时回滚 active，避免“同进程 Seal 用新 kid，重启又回旧 kid”。
	dir := t.TempDir()
	b := newBoxWithPersist(t, filepath.Join(dir, "ring.json"))
	mustAdd(t, b, "k1") // 正常落盘，active=k1

	// 把 persist 错配成已存在目录，触发 Rotate 落盘失败
	b.persist = persist.New(t.TempDir())

	before := b.ActiveKid()
	if err := b.Rotate("k2", "", []byte("0123456789abcdef0123456789abcdef")); err == nil {
		t.Fatalf("Rotate: 期望持久化失败错误，得到 nil")
	}
	after := b.ActiveKid()
	if after != before {
		t.Fatalf("Rotate 落盘失败后 active 撕裂：before=%q after=%q（应回滚到 %q）",
			before, after, before)
	}
	// 新 kid 不得残留在环里，否则重启 LoadPersist 后磁盘无此条目却内存有
	for _, e := range b.ring.List() {
		if e.ID == "k2" {
			t.Fatalf("Rotate 落盘失败后新密钥 k2 仍残留在环中")
		}
	}
}

func TestAdd_RollbackOnPersistFailure(t *testing.T) {
	b := newMisconfiguredBox(t)
	if err := b.Add("k1", "", []byte("0123456789abcdef0123456789abcdef")); err == nil {
		t.Fatalf("Add: 期望持久化失败错误，得到 nil")
	}
	if got := b.ActiveKid(); got != "" {
		t.Fatalf("Add 落盘失败后 active 应为空，得到 %q", got)
	}
	if n := b.ring.Len(); n != 0 {
		t.Fatalf("Add 落盘失败后环应回滚为空，Len=%d", n)
	}
}

func TestRevoke_RollbackOnPersistFailure(t *testing.T) {
	dir := t.TempDir()
	b := newBoxWithPersist(t, filepath.Join(dir, "ring.json"))
	mustAdd(t, b, "k1")
	if got := b.ActiveKid(); got != "k1" {
		t.Fatalf("setup: active=%q want k1", got)
	}

	// 把 persist 错配成目录，Revoke 落盘必然失败
	b.persist = persist.New(t.TempDir())

	if err := b.Revoke("k1"); err == nil {
		t.Fatalf("Revoke: 期望持久化失败错误，得到 nil")
	}
	// 回滚：k1 未被撤销、仍为 active
	e, ok := b.ring.Get("k1")
	if !ok {
		t.Fatalf("Revoke 回滚后 k1 应仍在环中")
	}
	if e.Revoked {
		t.Fatalf("Revoke 落盘失败后 k1 仍被标记为 revoked，未回滚")
	}
	if got := b.ActiveKid(); got != "k1" {
		t.Fatalf("Revoke 落盘失败后 active 撕裂：got=%q want k1", got)
	}
}

func TestRotate_PersistFailureKeepsOldActiveUsable(t *testing.T) {
	// 落盘失败后旧 active 必须仍可正常 Seal——即状态一致、未半切换。
	dir := t.TempDir()
	b := newBoxWithPersist(t, filepath.Join(dir, "ring.json"))
	mustAdd(t, b, "k1")

	b.persist = persist.New(t.TempDir()) // 错配，落盘必败
	_ = b.Rotate("k2", "", []byte("0123456789abcdef0123456789abcdef"))

	if got := b.ActiveKid(); got != "k1" {
		t.Fatalf("Rotate 失败后 active=%q，仍应为 k1", got)
	}
	bl, err := b.Seal([]byte("aad"), []byte("plain"))
	if err != nil {
		t.Fatalf("Seal after failed Rotate: %v", err)
	}
	if bl.Kid != "k1" {
		t.Fatalf("Seal Kid=%q，应仍用旧 active k1", bl.Kid)
	}
	plain, err := b.Open(bl)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(plain) != "plain" {
		t.Fatalf("roundtrip plain=%q", plain)
	}
}

func newBoxWithPersist(t *testing.T, path string) *Box {
	t.Helper()
	b, err := New(Options{Cipher: cipher.NewAESGCM(), PersistPath: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}
