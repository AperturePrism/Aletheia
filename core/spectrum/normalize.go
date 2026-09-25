// Package spectrum 实现 EvidenceSpectrum 的归一化与无损折叠（modules/M1 §4.4、§4.5）。
//
// 归一化是解析前的统一预处理：工具原始输出在进入任何解析器之前必须先经过
// 本包，保证「进入解析前统一 strip_ansi」（M1 §4.3 翻车点 2）与
// CRLF/LF/CR、非法 UTF-8、超长单行三类边界在同一处收口。
// 解析器不得各自内联处理这些边界 —— 那会让边界用例在每个适配器里漏掉一部分。
//
// 确定性（P-5）：本包全部函数是纯函数 —— 无 IO、无全局状态、无时间与随机依赖；
// 相同输入必得相同输出（Q6 的基础）。
package spectrum

import (
	"fmt"
	"unicode/utf8"
)

// DefaultMaxLineBytes 是单行字节上限（modules/M1 §8：超长单行截断并记 warning，
// 防止目标侧用超大响应撑爆内存 —— threat-model T9「资源耗尽」）。
const DefaultMaxLineBytes = 1 << 20 // 1 MiB

// CleanANSI 移除 ANSI 转义序列，保留其余字节原样（含换行结构）。
//
// 处理两类序列：
//   - CSI 序列：ESC [ 参数字节(0x30-0x3F) 中间字节(0x20-0x2F) 终止字节(0x40-0x7E)
//   - 其他以 ESC(0x1B) 开头的两字节序列（如 ESC c）
//
// 序列内不会出现换行（终端转义不跨行），因此行号在清洗前后保持不变 ——
// 这是 SpectrumLine.orig_line_* 能指向原始文件行号的前提。
// 未终止的截断序列（输出被截断的常见形态）按 ESC 起点整体移除。
func CleanANSI(b []byte) []byte {
	esc := -1 // 最近一个未处理 ESC 的下标；-1 表示无
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case esc >= 0:
			if c == '[' { // CSI 起点：吞到终止字节
				i++
				for ; i < len(b); i++ {
					p := b[i]
					if p >= 0x40 && p <= 0x7E {
						break
					}
				}
				esc = -1
			} else if c >= 0x20 && c <= 0x7E { // 两字节 ESC 序列
				esc = -1
			} else { // 异常字节：仅吞掉 ESC 本身，回退一格重新处理
				i--
				esc = -1
			}
		case c == 0x1B:
			esc = i
		default:
			out = append(out, c)
		}
	}
	return out
}

// SanitizeUTF8 把非法 UTF-8 字节替换为 utf8.RuneError（U+FFFD），
// 返回处理后内容与是否发生替换。调用方据后者追加 ParseQuality.warning。
// 替换保持字节位置对齐不成立（1 字节 → 3 字节），但**不产生/删除换行**，
// 行号不变。JSON/XML 的合法 \uXXXX 转义是 ASCII，不受影响。
func SanitizeUTF8(b []byte) ([]byte, bool) {
	if utf8.Valid(b) {
		return b, false
	}
	out := make([]byte, 0, len(b)+8)
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size <= 1 {
			out = append(out, []byte(string(utf8.RuneError))...)
			b = b[1:]
			continue
		}
		out = append(out, b[:size]...)
		b = b[size:]
	}
	return out, true
}

// SplitLines 把内容按 CRLF / LF / 孤立 CR 切分为不含行尾的行。
// 末尾有换行时不再产生空尾行；空输入产生空行集。
// 三种行尾混合是 M1 §6 边界用例之一（Windows 工具重定向输出常见）。
func SplitLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	var lines []string
	start := 0
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case '\r':
			lines = append(lines, string(b[start:i]))
			if i+1 < len(b) && b[i+1] == '\n' {
				i++
			}
			start = i + 1
		case '\n':
			lines = append(lines, string(b[start:i]))
			start = i + 1
		}
	}
	if start < len(b) {
		lines = append(lines, string(b[start:]))
	}
	return lines
}

// Normalize 是解析前的统一入口：UTF-8 消毒 → ANSI 清洗 → 超长行截断 → 切行。
//
// 返回的行列表是全部解析器的唯一输入形态；warnings 追加到 ParseQuality。
// 行号约定：返回行的下标 + 1 = 原始输出的物理行号
// （Sanitize/CleanANSI 均不产生或删除换行，截断不跨行，因此行号稳定）。
func Normalize(b []byte, maxLineBytes int) (lines []string, warnings []string) {
	s, fixed := SanitizeUTF8(b)
	if fixed {
		warnings = append(warnings, "input contained invalid UTF-8 bytes; replaced with U+FFFD")
	}
	s = CleanANSI(s)
	if maxLineBytes <= 0 {
		maxLineBytes = DefaultMaxLineBytes
	}
	lines = SplitLines(s)
	for i, ln := range lines {
		if len(ln) > maxLineBytes {
			lines[i] = ln[:maxLineBytes]
			warnings = append(warnings,
				fmt.Sprintf("line %d truncated beyond %d byte limit", i+1, maxLineBytes))
		}
	}
	return lines, warnings
}
