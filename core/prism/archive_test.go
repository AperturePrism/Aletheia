package prism

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// T2.7 / M2 §4.6 DoD⑤：归档后沿 downlink 恢复明细，结果与归档前一致。
func TestArchiveRestoreRoundTrip(t *testing.T) {
	s, clk := newTestStore(t)
	ctx := context.Background()

	// 造数据：三个 ASSET（不同 os 内容）+ 一个 SERVICE（RUNS_ON 关系）。
	before := ""
	for i, os := range []string{"linux", "bsd", "solaris"} {
		sp := spectrum("sp_arch_"+string(rune('a'+i)),
			assetDraft("10.40.23.1"+string(rune('a'+i)), 0.9),
			serviceDraft("10.40.23.1"+string(rune('a'+i)), "22", "ssh"+string(rune('a'+i)), 0.8))
		if i == 1 { // 让 os 有差异，保证属性值域非平凡
			sp.Entities[0].Attributes["os"] = os
		}
		if _, err := s.Ingest(ctx, sp); err != nil {
			t.Fatal(err)
		}
		clk.advance(2 * time.Millisecond)
	}
	sub, err := s.SnapshotAt(ctx, MainBranchID, clk.t, 1000)
	if err != nil {
		t.Fatal(err)
	}
	before = HashCanonical(sub.GetEntities(), sub.GetRelations())

	// 归档：把此刻之前写入的实体降采样。
	archiveID, archived, err := s.ArchiveStale(ctx, clk.t)
	if err != nil {
		t.Fatal(err)
	}
	if archiveID == "" || len(archived) < 3 {
		t.Fatalf("archive = %q, archived %d entities", archiveID, len(archived))
	}
	// 归档后：当前快照明细为空。
	afterArchive, err := s.SnapshotAt(ctx, MainBranchID, clk.t, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterArchive.GetEntities()) != 0 {
		t.Fatalf("archived entities must not appear in current snapshot, got %d",
			len(afterArchive.GetEntities()))
	}
	// 归档节点在册。
	archives, err := s.ListArchives(ctx)
	if err != nil || len(archives) != 2 {
		t.Fatalf("ListArchives = %v (ASSET/SERVICE 各一节点), err=%v", archives, err)
	}

	// 恢复：对每个归档节点执行（按 kind 分组 → 多节点），
	// 明细 valid_to 还原 → 指纹与归档前一致（DoD⑤）。
	restored := []string{}
	for _, aid := range archives {
		r, err := s.RestoreArchive(ctx, aid)
		if err != nil {
			t.Fatal(err)
		}
		restored = append(restored, r...)
	}
	if len(restored) != len(archived) {
		t.Fatalf("restored %d, want %d", len(restored), len(archived))
	}
	after, err := s.SnapshotAt(ctx, MainBranchID, clk.t, 1000)
	if err != nil {
		t.Fatal(err)
	}
	afterFP := HashCanonical(after.GetEntities(), after.GetRelations())
	if afterFP != before {
		t.Fatalf("restore fidelity violated: got %q want %q", afterFP, before)
	}
	// 归档节点已消费删除。
	if archives, _ := s.ListArchives(ctx); len(archives) != 0 {
		t.Fatalf("archive node must be removed after restore, got %v", archives)
	}
}

// TestArchiveStaleSkipsFreshEntities：晚于 olderThan 的实体不归档。
func TestArchiveStaleSkipsFreshEntities(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	sp := spectrum("sp_fresh", assetDraft("10.40.23.10", 0.9))
	if _, err := s.Ingest(ctx, sp); err != nil {
		t.Fatal(err)
	}
	// olderThan 在未来 → 实体尚未陈旧 → 空归档（不是错误）。
	archiveID, archived, err := s.ArchiveStale(ctx, clkNow(t)) // olderThan = 时钟起点：+2ms 的实体晚于它
	if err != nil {
		t.Fatal(err)
	}
	if archiveID != "" || len(archived) != 0 {
		t.Fatalf("fresh entities must not be archived, got %q/%v", archiveID, archived)
	}
}

// TestRestoreUnknownArchiveRefused：未知归档 ID 显式失败（fail-closed）。
func TestRestoreUnknownArchiveRefused(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.RestoreArchive(context.Background(), "arch_missing"); err == nil {
		t.Fatal("unknown archive must be refused explicitly")
	}
}

// TestArchiveDeterministicID：同一批实体的独立归档 → 同一 archive_id
// （内容寻址：幂等可审计）。
func TestArchiveDeterministicID(t *testing.T) {
	s1, _ := newTestStore(t)
	s2, _ := newTestStore(t)
	olderThan := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	for _, st := range []*Store{s1, s2} {
		sp := spectrum("sp_det",
			assetDraft("10.40.23.10", 0.9),
			serviceDraft("10.40.23.10", "22", "ssh", 0.8))
		sp.ObservedAt = timestamppb.New(olderThan.Add(-time.Hour))
		if _, err := st.Ingest(context.Background(), sp); err != nil {
			t.Fatal(err)
		}
	}
	id1, _, err := s1.ArchiveStale(context.Background(), olderThan)
	if err != nil {
		t.Fatal(err)
	}
	id2, _, err := s2.ArchiveStale(context.Background(), olderThan)
	if err != nil {
		t.Fatal(err)
	}
	if id1 == "" || id1 != id2 {
		t.Fatalf("deterministic archive id violated: %q vs %q", id1, id2)
	}
}

func clkNow(t *testing.T) time.Time {
	t.Helper()
	return time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
}
