// Package testutil 为解析器测试加载 fixtures。
//
// fixtures 的唯一真源在 tests/parsers/fixtures/（modules/M1 §6 规定：
// 所有原始输出样本存入该目录并标注来源工具版本；样本禁止包含真实目标信息）。
// Go 包内不再复制样本 —— 复制会造成「测试测的不是同一份数据」的漂移。
package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

// Fixture 读取 tests/parsers/fixtures/<tool>/<name>，测试失败即 Fatal。
func Fixture(t *testing.T, tool, name string) []byte {
	t.Helper()
	// 本包位于 core/ingest/testutil → 仓库根是 ../..。
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	path := filepath.Join(root, "tests", "parsers", "fixtures", tool, name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return b
}
