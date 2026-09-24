// Package checkpoint 提供统一的快照基础设施。
//
// 对应 modules/M6 横切能力层 I0 任务 T6.3：
//
//	检查点存储基础设施
//
// 职责边界（modules/M6 §9）：本包**只管存储与寻址**，不管各组件如何产生
// 快照内容。各组件自己提供序列化：
//
//	组件          快照方式
//	────────────  ─────────────────────────────────────────────
//	心智地图      版本号（M2 支持 SnapshotAt）
//	证据账本      append-only，按 ID 水位截断（不回滚）
//	预算          状态副本
//	TaskGraph     plan_revision + 序列化
//
// 存储：内容寻址 + 增量（仅存差异）。
//
// 为什么内容寻址：04 §I6 DoD③ 要求"rewind 到任一检查点后重跑，证据一致性
// 校验通过"。校验方式就是比对内容哈希 —— 没有内容寻址就没有可校验的哈希。
package checkpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrNotFound 快照不存在。
var ErrNotFound = errors.New("checkpoint: not found")

// Meta 是一个 checkpoint 的元数据。对应 05 §6.2 CheckpointInfo 的字段。
type Meta struct {
	// ID 快照 ID：cp_{uuid7}（05 §1.1）。
	ID string `json:"id"`
	// SessionID 会话 ID（sess_{uuid7}）。
	SessionID string `json:"session_id"`
	// Label 人可读标签。
	Label string `json:"label"`
	// CreatedAt RFC 3339 UTC（05 §1.2）。
	CreatedAt time.Time `json:"created_at"`

	// PlanRevision 计划版本（05 §6.1 TaskGraph.plan_revision）。
	PlanRevision string `json:"plan_revision"`
	// GraphVersion 心智地图版本号。
	GraphVersion uint64 `json:"graph_version"`
	// LedgerWatermark 证据账本按 ID 水位截断的边界（不回滚账本）。
	LedgerWatermark string `json:"ledger_watermark"`
	// BudgetSnapshotHash 预算状态副本的内容哈希。
	BudgetSnapshotHash string `json:"budget_snapshot_hash"`

	// Components 组件名 → 组件内容哈希。
	//
	// 不含内容本身（内容在 blobs/ 里），只存哈希。这样 Meta 本身很小，
	// 且"这个 checkpoint 有哪些组件、各是什么内容"可脱离 blob 独立审阅。
	Components map[string]string `json:"components"`

	// ContentHash 全部组件内容的聚合哈希。
	// rewind 后的证据一致性校验就基于这个值（04 §I6 DoD③）。
	ContentHash string `json:"content_hash"`
}

// Component 是一份快照内容。
type Component struct {
	// Name 组件名，如 "taskgraph" / "budget" / "map_version"。
	Name string `json:"name"`
	// Data 组件内容。调用方负责序列化（契约各自的格式）。
	Data []byte `json:"-"`
}

// Store 是基于文件系统的内容寻址 checkpoint 存储。
//
// 目录布局：
//
//	<root>/index/<session_id>/<checkpoint_id>.json   Meta（含各组件哈希）
//	<root>/blobs/<sha256前2位>/<sha256>              内容块（组件数据）
//
// 幂等：相同内容的组件只存一份（内容寻址天然去重）。
type Store struct {
	root string
	mu   sync.RWMutex
	// index 缓存 session -> checkpoint -> Meta，避免每次读盘。
	index map[string]map[string]Meta
}

// NewStore 打开（必要时创建）一个 checkpoint 存储。
func NewStore(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("checkpoint: root is empty")
	}
	for _, d := range []string{
		filepath.Join(root, "index"),
		filepath.Join(root, "blobs"),
	} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("checkpoint: mkdir %q: %w", d, err)
		}
	}
	s := &Store{
		root:  root,
		index: make(map[string]map[string]Meta),
	}
	if err := s.loadIndex(); err != nil {
		return nil, err
	}
	return s, nil
}

// Save 保存一个 checkpoint。相同 ID 重复保存是幂等的
// （内容一致则不做事，不一致则报错 —— 快照不可变）。
func (s *Store) Save(meta Meta, components []Component) (Meta, error) {
	if strings.TrimSpace(meta.SessionID) == "" {
		return Meta{}, errors.New("checkpoint: session_id is empty")
	}
	if strings.TrimSpace(meta.ID) == "" {
		return Meta{}, errors.New("checkpoint: id is empty")
	}
	if meta.CreatedAt.IsZero() {
		meta.CreatedAt = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	componentHashes := make(map[string]string, len(components))
	for _, c := range components {
		sum, err := hashBytes(c.Data)
		if err != nil {
			return Meta{}, err
		}
		componentHashes[c.Name] = sum
	}

	hash, err := aggregateHash(components)
	if err != nil {
		return Meta{}, err
	}
	meta.Components = componentHashes
	meta.ContentHash = hash

	for _, c := range components {
		p := s.blobPath(componentHashes[c.Name])
		if _, err := os.Stat(p); err == nil {
			continue // 内容寻址去重
		}
		// shard 子目录按需创建（blobs/<hash 前 2 位>/）。
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return Meta{}, fmt.Errorf("checkpoint: mkdir blob shard for %s: %w", c.Name, err)
		}
		if err := os.WriteFile(p, c.Data, 0o600); err != nil {
			return Meta{}, fmt.Errorf("checkpoint: write blob for %s: %w", c.Name, err)
		}
	}

	if existing, ok := s.index[meta.SessionID][meta.ID]; ok {
		// 快照不可变：ID 已存在且内容不同 → 错误，不允许静默覆盖。
		if existing.ContentHash != meta.ContentHash {
			return Meta{}, fmt.Errorf(
				"checkpoint: id %q already exists with different content (existing %s, new %s)",
				meta.ID, existing.ContentHash, meta.ContentHash)
		}
		return existing, nil
	}

	if err := s.writeMeta(meta); err != nil {
		return Meta{}, err
	}

	if s.index[meta.SessionID] == nil {
		s.index[meta.SessionID] = make(map[string]Meta)
	}
	s.index[meta.SessionID][meta.ID] = meta
	return meta, nil
}

// Get 读取一个 checkpoint 的元数据。
func (s *Store) Get(sessionID, checkpointID string) (Meta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lockedGet(sessionID, checkpointID)
}

func (s *Store) lockedGet(sessionID, checkpointID string) (Meta, error) {
	m, ok := s.index[sessionID][checkpointID]
	if !ok {
		return Meta{}, fmt.Errorf("%w: session=%s checkpoint=%s", ErrNotFound, sessionID, checkpointID)
	}
	return m, nil
}

// List 列出某会话的全部 checkpoint，按创建时间升序（确定性顺序）。
//
// 关于排序的确定性（P-5）：CreatedAt 用 time.Now() 取得，同一批次创建的
// checkpoint 时间戳可能只差纳秒。若只用时间排序，"顺序确定"就不成立 ——
// 而这会影响 rewind 的"取最近一个"等逻辑。
//
// 因此排序规则为：先比时间，**时间舍入到秒后比较**，相同则按 ID。
// 舍入到秒的理由：checkpoint 是人触发的粗粒度操作，秒级精度足够，
// 而纳秒级差异只带来不确定性。
func (s *Store) List(sessionID string) []Meta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Meta, 0, len(s.index[sessionID]))
	for _, m := range s.index[sessionID] {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		ti := out[i].CreatedAt.Truncate(time.Second).Unix()
		tj := out[j].CreatedAt.Truncate(time.Second).Unix()
		if ti != tj {
			return ti < tj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Latest 返回某会话最近的 checkpoint。无则 ErrNotFound。
func (s *Store) Latest(sessionID string) (Meta, error) {
	all := s.List(sessionID)
	if len(all) == 0 {
		return Meta{}, fmt.Errorf("%w: session=%s has no checkpoints", ErrNotFound, sessionID)
	}
	return all[len(all)-1], nil
}

// LoadComponents 读出一个 checkpoint 的全部组件内容。
func (s *Store) LoadComponents(sessionID, checkpointID string) ([]Component, error) {
	s.mu.RLock()
	meta, err := s.lockedGet(sessionID, checkpointID)
	s.mu.RUnlock()
	if err != nil {
		return nil, err
	}

	// 组件名按字典序排列，保证遍历顺序确定（P-5 确定性）。
	names := make([]string, 0, len(meta.Components))
	for n := range meta.Components {
		names = append(names, n)
	}
	sort.Strings(names)

	out := make([]Component, 0, len(names))
	for _, n := range names {
		ref := s.blobPath(meta.Components[n])
		data, err := os.ReadFile(ref)
		if err != nil {
			// 内容块缺失 = 存储损坏。fail-closed：报错而不是返回空组件，
			// 否则 rewind 会"成功"回到一个不完整的过去。
			return nil, fmt.Errorf("checkpoint: component %q of %s: blob missing (%s): %w",
				n, checkpointID, ref, err)
		}
		// 逐组件校验：内容哈希必须与 Meta 记录一致。
		actual, err := hashBytes(data)
		if err != nil {
			return nil, err
		}
		if actual != meta.Components[n] {
			return nil, fmt.Errorf("checkpoint: component %q of %s: hash mismatch (meta=%s actual=%s)",
				n, checkpointID, meta.Components[n], actual)
		}
		out = append(out, Component{Name: n, Data: data})
	}
	return out, nil
}

// Verify 校验 checkpoint 的完整性：重新计算内容哈希并与 Meta 比对。
//
// 这是 04 §I6 DoD③「rewind 到任一检查点后重跑，证据一致性校验通过」的
// 基础操作。
func (s *Store) Verify(sessionID, checkpointID string) error {
	s.mu.RLock()
	meta, err := s.lockedGet(sessionID, checkpointID)
	s.mu.RUnlock()
	if err != nil {
		return err
	}

	components, err := s.LoadComponents(sessionID, checkpointID)
	if err != nil {
		return err
	}
	got, err := aggregateHash(components)
	if err != nil {
		return err
	}
	if got != meta.ContentHash {
		return fmt.Errorf("checkpoint: content hash mismatch for %s: meta=%s actual=%s",
			checkpointID, meta.ContentHash, got)
	}
	return nil
}

// ---- 内部 ----

// aggregateHash 计算组件集合的聚合哈希。
//
// 与 Meta.componentHash / componentNames 的实现必须一致 —— 三者共同决定
// 聚合哈希的算法，任一处改动都会让旧 checkpoint 全部校验失败。
// 算法固定为：按组件名排序后，逐块 sha256( "name\x00len\x00" + data )。
func aggregateHash(components []Component) (string, error) {
	sorted := make([]Component, len(components))
	copy(sorted, components)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	h := sha256.New()
	for _, c := range sorted {
		if _, err := fmt.Fprintf(h, "%s\x00%d\x00", c.Name, len(c.Data)); err != nil {
			return "", err
		}
		if _, err := h.Write(c.Data); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashBytes(b []byte) (string, error) {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (s *Store) blobPath(sum string) string {
	if len(sum) < 2 {
		// 防御：不应发生（sha256 hex 恒为 64 字符）。
		return filepath.Join(s.root, "blobs", sum)
	}
	return filepath.Join(s.root, "blobs", sum[:2], sum)
}

func (s *Store) metaPath(sessionID, checkpointID string) string {
	// session_id 与 checkpoint_id 用于文件名，须剔除路径分隔符。
	return filepath.Join(s.root, "index",
		safeName(sessionID), safeName(checkpointID)+".json")
}

func (s *Store) writeMeta(meta Meta) error {
	p := s.metaPath(meta.SessionID, meta.ID)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("checkpoint: mkdir %q: %w", filepath.Dir(p), err)
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("checkpoint: marshal meta: %w", err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return fmt.Errorf("checkpoint: write meta %q: %w", p, err)
	}
	return nil
}

func (s *Store) loadIndex() error {
	root := filepath.Join(s.root, "index")
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("checkpoint: read index dir: %w", err)
	}
	for _, sess := range entries {
		if !sess.IsDir() {
			continue
		}
		sessionID := sess.Name()
		sub := filepath.Join(root, sessionID)
		files, err := os.ReadDir(sub)
		if err != nil {
			return fmt.Errorf("checkpoint: read %q: %w", sub, err)
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(sub, f.Name()))
			if err != nil {
				return fmt.Errorf("checkpoint: read %q: %w", f.Name(), err)
			}
			var m Meta
			if err := json.Unmarshal(data, &m); err != nil {
				return fmt.Errorf("checkpoint: parse %q: %w", f.Name(), err)
			}
			if s.index[m.SessionID] == nil {
				s.index[m.SessionID] = make(map[string]Meta)
			}
			s.index[m.SessionID][m.ID] = m
		}
	}
	return nil
}

func safeName(s string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", "..", "_", string(os.PathSeparator), "_")
	return r.Replace(s)
}
