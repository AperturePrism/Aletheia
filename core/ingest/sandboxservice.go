// SandboxService —— 05 §6.3 [frozen] 契约的实现（M6 §7.2 的签发边界）。
//
// 职责（契约原文）：exec_id 的唯一合法签发者。
//
//	· SignExecId —— 预签发一个 exec_id（执行前获取，入账时携带签名）；
//	· Execute —— 参数渲染（Schema）→ 隔离执行 → exec_id + 签名 +
//	  stdout/stderr 内容寻址引用。scope 校验由调用方完成（契约注释：
//	  请求携带「已归一化并通过 scope 校验的参数」），Sandbox 不重复。
//
// 签名域与 focalplane 的 Ed25519Verifier 字节级一致
// （agents/src/aletheia/focalplane/execverifier.py 的
// EXEC_ID_SIGN_DOMAIN = b"aleth/exec-id/v1\x00"）—— M4 独立验签的
// 前提是两侧共享同一域分离约定；测试用固定字节断言防止漂移。
package ingest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/AperturePrism/aleth/core/api/aleth/v1"
	"github.com/AperturePrism/aleth/core/spectrum"
)

// ExecIDSignDomain 是 exec_id 签名的域分离前缀。
// 与 focalplane execverifier.EXEC_ID_SIGN_DOMAIN 字节一致（含结尾 NUL）。
var ExecIDSignDomain = []byte("aleth/exec-id/v1\x00")

// ExecSigner 以 Ed25519 私钥签发 exec_id（私钥仅在 Sandbox 进程内，
// M6 §7.2；「进程内」的进程边界在容器化部署形态下即容器边界）。
type ExecSigner struct {
	priv ed25519.PrivateKey
}

// LoadExecSignerFromHex 从 hex 编码的原始私钥加载（32 字节）。
func LoadExecSignerFromHex(hexKey string) (*ExecSigner, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil {
		return nil, fmt.Errorf("sandbox: exec key hex: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf(
			"sandbox: exec key must be %d bytes (raw ed25519), got %d",
			ed25519.PrivateKeySize, len(raw))
	}
	return &ExecSigner{priv: ed25519.PrivateKey(raw)}, nil
}

// LoadExecSignerFromFile 读取仅含 hex 私钥的文件。
func LoadExecSignerFromFile(path string) (*ExecSigner, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sandbox: read exec key file: %w", err)
	}
	return LoadExecSignerFromHex(string(data))
}

// GenerateExecSigner 生成新密钥对（无密钥文件时的默认：每次启动一对，
// 公钥随启动日志输出 —— 交付给 focalplane 验签侧）。
func GenerateExecSigner() (*ExecSigner, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sandbox: generate exec key: %w", err)
	}
	return &ExecSigner{priv: priv}, nil
}

// PublicKeyHex 返回公钥（hex），用于配置 focalplane 验签侧。
func (s *ExecSigner) PublicKeyHex() string {
	return hex.EncodeToString(s.priv.Public().(ed25519.PublicKey))
}

// Verify 用自身公钥验签（测试与自检用；生产验签在 focalplane）。
func (s *ExecSigner) Verify(execID, sigHex string) bool {
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	return ed25519.Verify(s.priv.Public().(ed25519.PublicKey), signInput(execID), sig)
}

func (s *ExecSigner) sign(execID string) string {
	return hex.EncodeToString(ed25519.Sign(s.priv, signInput(execID)))
}

func signInput(execID string) []byte {
	out := make([]byte, 0, len(ExecIDSignDomain)+len(execID))
	out = append(out, ExecIDSignDomain...)
	out = append(out, execID...)
	return out
}

// SandboxFullRunner 是 SandboxService 消费的执行形态（完整输出 + 退出码，
// 供「失败也把证据抛出来」的契约语义）。*ProcessSandbox 天然实现；
// 测试注入 fake；Docker/Kata 后端实现同一接口即可替换。
type SandboxFullRunner interface {
	ExecuteFull(
		ctx context.Context, toolName string, argv []string,
	) (execID string, stdout, stderr []byte, exitCode int, err error)
}

// SandboxService 实现 alethv1.SandboxServiceServer。
type SandboxService struct {
	alethv1.UnimplementedSandboxServiceServer

	catalog *Catalog
	store   *RawStore
	runner  SandboxFullRunner
	signer  *ExecSigner
}

// NewSandboxService 装配 SandboxService。
func NewSandboxService(catalog *Catalog, store *RawStore, runner SandboxFullRunner, signer *ExecSigner) *SandboxService {
	return &SandboxService{catalog: catalog, store: store, runner: runner, signer: signer}
}

// SignExecId 预签发：生成新 exec_id 并签名。
// purpose 记入调用方审计语境（本实现以日志呈现；持久审计随 I3 审计层）。
func (s *SandboxService) SignExecId(ctx context.Context, req *alethv1.SignExecIdRequest) (*alethv1.SignedExecId, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	execID, err := newExecID()
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("sandbox: %v", err))
	}
	out := &alethv1.SignedExecId{
		ExecId:    execID,
		Signature: s.signer.sign(execID),
		IssuedAt:  timeNowPb(),
	}
	return out, nil
}

// Execute：Schema 渲染 → 隔离执行 → 签发 + 内容寻址引用。
// 契约注释：「必须非零码退出并把证据抛出来」—— 工具失败时输出引用
// 仍然返回（证据不因失败而丢弃），exit_code 与 error 一并给出。
func (s *SandboxService) Execute(ctx context.Context, req *alethv1.SandboxExecRequest) (*alethv1.SandboxExecResult, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}
	adapter, ok := s.catalog.Get(req.GetToolName())
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument,
			"unknown tool %q; see IngestService.ListAdapters for the allowlist", req.GetToolName())
	}
	normalized, err := adapter.Schema().Validate(req.GetParams())
	if err != nil {
		return nil, toGRPC(err)
	}
	argv, err := adapter.RenderArgv(normalized)
	if err != nil {
		return nil, toGRPC(err)
	}

	execID, stdout, stderr, exitCode, runErr := s.runner.ExecuteFull(ctx, req.GetToolName(), argv)

	result := &alethv1.SandboxExecResult{ExecId: execID, ExitCode: int32(exitCode)}
	if execID != "" {
		result.Signature = s.signer.sign(execID)
	}
	if hash, uri, err := s.store.Put(stdout); err == nil {
		result.StdoutRef = &alethv1.RawOutputRef{
			ContentHash: hash,
			StorageUri:  uri,
			SizeBytes:   uint64(len(stdout)),
			LineCount:   uint32(len(spectrum.SplitLines(stdout))),
		}
	}
	if len(stderr) > 0 {
		if hash, uri, err := s.store.Put(stderr); err == nil {
			result.StderrRef = &alethv1.RawOutputRef{
				ContentHash: hash,
				StorageUri:  uri,
				SizeBytes:   uint64(len(stderr)),
				LineCount:   uint32(len(spectrum.SplitLines(stderr))),
			}
		}
	}
	if runErr != nil {
		result.Error = &alethv1.Error{
			Code:    alethv1.ErrorCode_UPSTREAM_UNAVAILABLE,
			Message: runErr.Error(),
		}
	}
	return result, nil
}

func timeNowPb() *timestamppb.Timestamp {
	return timestamppb.New(time.Now().UTC())
}
