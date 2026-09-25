package ingest

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"github.com/AperturePrism/aleth/core/spectrum"
)

// sha256Hex 是内容寻址的哈希函数（05 §2.1 content_hash）。
// 基于原始字节而非解析后结构（M1 §4.5）。
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// argvHash 是 ToolInvocation.argv_hash 的输入变换：以 NUL 连接各元素，
// 避免 "ab","c" 与 "a","bc" 的歧义。
func argvHash(argv []string) string {
	h := sha256.New()
	for i, a := range argv {
		if i > 0 {
			h.Write([]byte{0})
		}
		h.Write([]byte(a))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// LineStartTable 返回内容中每行首字节的偏移表（升序），供 InputOffset → 行号。
// 行号一律 1-based，与「下标 + 1 = 物理行号」的约定一致。
func LineStartTable(b []byte) []int64 {
	table := []int64{0}
	for i, c := range b {
		if c == '\n' {
			table = append(table, int64(i)+1)
		}
	}
	return table
}

// LineAt 用二分把字节偏移映射为行号（1-based）。
func LineAt(table []int64, off int64) uint32 {
	// 最后一个 <= off 的行首。
	i := sort.Search(len(table), func(i int) bool { return table[i] > off }) - 1
	if i < 0 {
		i = 0
	}
	return uint32(i + 1)
}

// Quality 组装 ParseQuality。coverage = 识别单元 / 总有效单元；
// total == 0（空输出）是合法观测，coverage 记 1（04 §I1 DoD① 的空输出边界）。
func Quality(total, unparsed int, warnings []string) *alethv1.ParseQuality {
	coverage := 1.0
	if total > 0 {
		coverage = float64(total-unparsed) / float64(total)
	}
	return &alethv1.ParseQuality{
		Coverage:      coverage,
		UnparsedLines: uint32(unparsed),
		Warnings:      warnings,
	}
}

// RawRecord 把无法解析的原始行保留为一条未折叠记录 ——
// 无损要求：任何行都不允许静默消失（M1 §4.3「不得静默丢弃」）。
func RawRecord(lineNo uint32, text string) spectrum.Record {
	return spectrum.Record{
		OrigLineStart: lineNo,
		OrigLineEnd:   lineNo,
		Template:      "raw " + text,
		FoldCount:     1,
	}
}

// newSpectrumID 生成 sp_{uuid7}（05 §1.1）。uuid7 内含毫秒时间戳，天然有序，
// 便于账本 append-only 与范围查询；随机位来自 crypto/rand。
// （10 §P4：确定性路径的 uuid 与审计时间戳豁免 —— spectrum_id 是执行上下文
// 标识，不是解析产物，不参与 Q6 字节级一致性对比。）
func newSpectrumID() string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], uint64(time.Now().UnixMilli())&0xFFFF_FFFF_FFFF)
	if _, err := rand.Read(b[8:]); err != nil {
		// crypto/rand 失败是系统级异常：fail-closed，向上传播（09 §6 #2）。
		panic(fmt.Sprintf("ingest: crypto/rand unavailable: %v", err))
	}
	b[6] = (b[6] & 0x0F) | 0x70 // version 7
	b[8] = (b[8] & 0x3F) | 0x80 // RFC 4122 variant
	return "sp_" + formatUUID(b)
}

func formatUUID(b [16]byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 36)
	for i, v := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, hex[v>>4], hex[v&0x0F])
	}
	return string(out)
}

// RawStore 是证据原始输出的内容寻址存储（05 §2.1 RawOutputRef.storage_uri，
// 「本地内容寻址存储」）。相同内容幂等：哈希即文件名。
type RawStore struct {
	dir string
}

// NewRawStore 建立/打开存储根目录。目录不可用时在这里显式失败
// （fail-closed），不允许执行成功但证据丢失。
func NewRawStore(dir string) (*RawStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create evidence dir: %w", err)
	}
	return &RawStore{dir: dir}, nil
}

// Put 写入内容并返回 sha256 哈希与存储 URI。
func (s *RawStore) Put(content []byte) (hash, uri string, err error) {
	sum := sha256Hex(content)
	sub := filepath.Join(s.dir, sum[:2])
	if err := os.MkdirAll(sub, 0o700); err != nil {
		return "", "", fmt.Errorf("create blob dir: %w", err)
	}
	path := filepath.Join(sub, sum)
	if _, statErr := os.Stat(path); statErr == nil { // 内容寻址：已存在即命中
		return sum, path, nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		return "", "", fmt.Errorf("write blob: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", "", fmt.Errorf("finalize blob: %w", err)
	}
	return sum, path, nil
}
