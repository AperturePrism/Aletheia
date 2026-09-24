package checkpoint

import (
	"os"
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

func sampleMeta(id, session string) Meta {
	return Meta{
		ID:           id,
		SessionID:    session,
		Label:        "label-" + id,
		PlanRevision: "rev-1",
		GraphVersion: 3,
	}
}

func sampleComponents() []Component {
	return []Component{
		{Name: "taskgraph", Data: []byte(`{"tasks":["recon"]}`)},
		{Name: "budget", Data: []byte(`{"total":1000}`)},
		{Name: "map_version", Data: []byte(`3`)},
	}
}

func TestSaveAndGet(t *testing.T) {
	s := newTestStore(t)

	saved, err := s.Save(sampleMeta("cp_1", "sess_1"), sampleComponents())
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if saved.ContentHash == "" {
		t.Fatal("ContentHash must be computed")
	}

	got, err := s.Get("sess_1", "cp_1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ContentHash != saved.ContentHash {
		t.Errorf("hash mismatch: got %s want %s", got.ContentHash, saved.ContentHash)
	}
}

// TestSaveIsIdempotent 验证相同内容重复保存是幂等的。
func TestSaveIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	first, err := s.Save(sampleMeta("cp_1", "sess_1"), sampleComponents())
	if err != nil {
		t.Fatalf("first Save: %v", err)
	}
	second, err := s.Save(sampleMeta("cp_1", "sess_1"), sampleComponents())
	if err != nil {
		t.Fatalf("second Save should be idempotent: %v", err)
	}
	if first.ContentHash != second.ContentHash {
		t.Errorf("idempotent save produced different hash: %s vs %s", first.ContentHash, second.ContentHash)
	}
}

// TestSaveRejectsMutation 验证快照不可变：同 ID 不同内容必须报错。
//
// 这是 rewind 可信的前提 —— 如果能静默覆盖，所谓"回到过去"就不可信了。
func TestSaveRejectsMutation(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Save(sampleMeta("cp_1", "sess_1"), sampleComponents()); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	different := []Component{{Name: "taskgraph", Data: []byte(`{"tasks":["other"]}`)}}
	if _, err := s.Save(sampleMeta("cp_1", "sess_1"), different); err == nil {
		t.Fatal("saving different content under an existing id must fail")
	}
}

// TestComponentOrderIndependence 验证组件顺序不影响聚合哈希。
//
// 若不成立，组装顺序不同的同一份状态会被判为不同快照，
// rewind 一致性校验会误报。
func TestComponentOrderIndependence(t *testing.T) {
	s := newTestStore(t)
	a := []Component{{Name: "x", Data: []byte("1")}, {Name: "y", Data: []byte("2")}}
	b := []Component{{Name: "y", Data: []byte("2")}, {Name: "x", Data: []byte("1")}}

	h1, err := s.Save(Meta{ID: "cp_a", SessionID: "s"}, a)
	if err != nil {
		t.Fatalf("Save a: %v", err)
	}
	h2, err := s.Save(Meta{ID: "cp_b", SessionID: "s"}, b)
	if err != nil {
		t.Fatalf("Save b: %v", err)
	}
	if h1.ContentHash != h2.ContentHash {
		t.Errorf("aggregate hash must not depend on component order: %s vs %s", h1.ContentHash, h2.ContentHash)
	}
}

func TestLoadComponents(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Save(sampleMeta("cp_1", "sess_1"), sampleComponents()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.LoadComponents("sess_1", "cp_1")
	if err != nil {
		t.Fatalf("LoadComponents: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d components, want 3", len(got))
	}
	// 顺序必须确定（按名排序），否则调用方解析结果不稳定。
	want := []string{"budget", "map_version", "taskgraph"}
	for i, w := range want {
		if got[i].Name != w {
			t.Errorf("component %d = %q, want %q (order must be deterministic)", i, got[i].Name, w)
		}
	}
}

// TestVerifyDetectsTampering 是 I6 DoD③ 的基础：
// rewind 后证据一致性校验必须能发现内容被改。
func TestVerifyDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	saved, err := s.Save(sampleMeta("cp_1", "sess_1"), sampleComponents())
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := s.Verify("sess_1", "cp_1"); err != nil {
		t.Fatalf("Verify on intact store: %v", err)
	}

	// 篡改 blob 内容（模拟存储损坏或恶意修改）。
	blob := filepath.Join(dir, "blobs", saved.Components["budget"][:2], saved.Components["budget"])
	if err := os.WriteFile(blob, []byte(`{"total":999999}`), 0o600); err != nil {
		t.Fatalf("tamper blob: %v", err)
	}

	if err := s.Verify("sess_1", "cp_1"); err == nil {
		t.Fatal("Verify must detect tampered blob content")
	}
}

// TestMissingBlobFailsClosed 验证内容块缺失时报错而非返回空组件。
//
// fail-closed：否则 rewind 会"成功"回到一个不完整的过去。
func TestMissingBlobFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	saved, err := s.Save(sampleMeta("cp_1", "sess_1"), sampleComponents())
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	for name, sum := range saved.Components {
		p := filepath.Join(dir, "blobs", sum[:2], sum)
		if err := os.Remove(p); err != nil {
			t.Fatalf("remove blob for %s: %v", name, err)
		}
	}
	if _, err := s.LoadComponents("sess_1", "cp_1"); err == nil {
		t.Fatal("missing blob must produce an error, not empty components")
	}
}

// TestPersistsAcrossReopen 验证重启后索引可恢复。
//
// daemon 重启是常态（24h/143h 稳定性测试会反复启停）。
func TestPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()

	s1, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore #1: %v", err)
	}
	saved, err := s1.Save(sampleMeta("cp_1", "sess_1"), sampleComponents())
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	s2, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore #2: %v", err)
	}
	got, err := s2.Get("sess_1", "cp_1")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if got.ContentHash != saved.ContentHash {
		t.Errorf("hash lost across reopen: %s vs %s", got.ContentHash, saved.ContentHash)
	}
	if err := s2.Verify("sess_1", "cp_1"); err != nil {
		t.Errorf("Verify after reopen: %v", err)
	}
}

func TestListOrdering(t *testing.T) {
	s := newTestStore(t)
	for _, id := range []string{"cp_b", "cp_a", "cp_c"} {
		if _, err := s.Save(sampleMeta(id, "sess_1"), sampleComponents()); err != nil {
			t.Fatalf("Save %s: %v", id, err)
		}
	}
	all := s.List("sess_1")
	if len(all) != 3 {
		t.Fatalf("got %d checkpoints, want 3", len(all))
	}
	// 同批次创建（时间戳相同）时必须按 ID 排序，保证顺序确定。
	if all[0].ID != "cp_a" || all[2].ID != "cp_c" {
		t.Errorf("ordering not deterministic: %s, %s, %s", all[0].ID, all[1].ID, all[2].ID)
	}
}

func TestNotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Get("nope", "nope"); err == nil {
		t.Error("Get on missing checkpoint must fail")
	}
	if _, err := s.Latest("nope"); err == nil {
		t.Error("Latest on empty session must fail")
	}
}

// TestContentAddressingDedupes 验证相同内容只存一份。
func TestContentAddressingDedupes(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	comps := []Component{{Name: "a", Data: []byte("shared")}}
	for _, id := range []string{"cp_1", "cp_2"} {
		if _, err := s.Save(Meta{ID: id, SessionID: "s"}, comps); err != nil {
			t.Fatalf("Save %s: %v", id, err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatalf("read blobs: %v", err)
	}
	total := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub, err := os.ReadDir(filepath.Join(dir, "blobs", e.Name()))
		if err != nil {
			t.Fatalf("read blob shard: %v", err)
		}
		total += len(sub)
	}
	if total != 1 {
		t.Errorf("content-addressed store should hold 1 blob for identical content, got %d", total)
	}
}
