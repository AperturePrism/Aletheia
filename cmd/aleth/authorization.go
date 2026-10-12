package main

// 授权凭证的 CLI 侧预校验与退出码约定（`docs/08` §1.1/§1.3）。
//
// # 为什么 CLI 需要自己校验一次凭证
//
// 校验的**权威实现**在 `core/scopekernel.ValidateROEFile`，
// 而 daemon 也调它 —— 防线在那边。
//
// 但 CLI 若不校验，会出现一个很糟的失败形态（实测确认）：
//
//	$ aleth daemon start --authorization 损坏的.yaml
//	alethd started (pid 61744), listening on 127.0.0.1:7723   ← 谎报
//	$ echo $?
//	0                                                          ← 假成功
//	（daemon 实际已崩溃退出，只在日志里有 yaml 解析错误）
//
// 对 `06` §3.2 的「④ CI 集成」这是致命的：CI 看到 exit 0 + "started"
// 就继续下一步，然后在某个**无关的**步骤失败 —— 排查方向被完全带偏。
//
// 因此 CLI 在启动前用**同一个** `ValidateROEFile` 校验一次，
// 把"daemon 起不来"变成"CLI 明确拒绝并给出退出码 3"。
//
// # 为什么复用而不是自己写一份
//
// 两套校验必然漂移，而漂移的那一侧就是"CLI 说合法、daemon 说非法"
// 的分歧 —— 那正是本文件要消除的问题。因此直接调同一个函数。
//
// # 退出码（`docs/08` §1.3）
//
// 凭证相关的拒绝一律 **3**，而不是通用的 1 —— 那让 CI 能区分
// "凭证有问题"（修配置）与"程序出错"（查 bug）。`08` §1.3 的流程图里，
// 四种拒绝情形（未提供 / 不可读 / 过期 / 字段不全）全部指向退出码 3。

import (
	"errors"
	"fmt"
	"time"

	"github.com/AperturePrism/aleth/core/scopekernel"
)

// exitCredentialRejected 是 `docs/08` §1.3 规定的凭证拒绝退出码。
const exitCredentialRejected = 3

// credentialError 表示一次凭证校验失败。
//
// 单独的类型（而非裸 error）是为了让 `main` 能把它映射成退出码 3，
// 而不必靠字符串匹配 —— 字符串匹配会在改文案时静默失效。
type credentialError struct {
	// Reason 人类可读的原因（含修复指引）。
	Reason string
	// Cause 底层错误（可能为 nil）。
	Cause error
}

func (e *credentialError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s\n  底层错误: %v", e.Reason, e.Cause)
	}
	return e.Reason
}

func (e *credentialError) Unwrap() error { return e.Cause }

// validateAuthorization 预校验授权凭证（`08` §1.3 的四种拒绝情形）。
//
// 委托给 `scopekernel.ValidateROEFile` —— daemon 用的是同一个函数，
// 因此不存在"CLI 与 daemon 校验口径不同"的分歧。
func validateAuthorization(authPath string) error {
	if authPath == "" {
		return &credentialError{Reason: "Authorization Anchor: 拒绝启动 —— 未提供授权凭证\n" +
			"  依据 docs/08 §1.1：无凭证不启动，不是警告、不是降级。\n" +
			"  用法：aleth daemon start --authorization roe.yaml\n" +
			"  凭证格式见 docs/08 §2；JSON Schema 见 docs/schemas/roe.schema.json"}
	}

	// 完整校验：targets 段 + authorization 段时间窗。
	//
	// 时间窗这一项此前**全项目无人校验** —— roe.schema.json 把它
	// 明确指派给 Scope Kernel（"跨度上限无法在 JSON Schema 内表达，
	// 由 Scope Kernel 强制"），但代码里搜不到任何 valid_until 的使用。
	if err := scopekernel.ValidateROEFile(authPath, time.Now().UTC()); err != nil {
		return &credentialError{
			Reason: fmt.Sprintf("授权凭证校验失败: %s", authPath) +
				"\n  依据 docs/08 §1.3：校验不通过即拒绝启动（退出码 3）。" +
				"\n  逐项判据：文件可读 / targets 至少一个 include 目标 /" +
				"\n  valid_until > valid_from / 跨度 ≤ 90 天 / 当前时刻在窗口内。" +
				"\n  示例：examples/roe.example.yaml" +
				"\n  Schema：docs/schemas/roe.schema.json",
			Cause: err,
		}
	}
	return nil
}

// asCredentialError 提取 credentialError（供 main 决定退出码）。
func asCredentialError(err error) (*credentialError, bool) {
	var ce *credentialError
	if errors.As(err, &ce) {
		return ce, true
	}
	return nil, false
}
