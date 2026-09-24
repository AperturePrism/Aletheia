// Package config 提供 alethd 与 aleth 共用的配置系统。
//
// 对应 modules/M6 横切能力层 I0 任务 T6.1：
//
//	配置系统 + 结构化日志（含脱敏日志格式）
//
// 设计依据：
//
//   - 06 §5「部署形态」：单机模式（默认）与团队模式共用同一套 schema 与代码，
//     通过配置切换驱动。
//   - 02 §7.5 / D18「零遥测默认」：默认不发送任何遥测。本包不提供任何
//     向外部发送配置或状态的代码路径。
//   - 02 §11.3 / D19「默认配置不安全」：默认仅监听 127.0.0.1；
//     无 TLS 证书时拒绝对外暴露而非自签降级。
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// 部署模式（06 §5）。
type DeployMode string

const (
	// ModeSingle 单机模式（默认）—— 面向个人研究者 / 学生 / CTF。
	// 存储 SQLite（WAL）+ 文件系统内容寻址；无外部数据库。
	ModeSingle DeployMode = "single"
	// ModeTeam 团队模式 —— 面向企业红队。PostgreSQL + 多用户 + 强制 TLS。
	// 注意：06 §5.2 明确团队模式「适用迭代 P3 之后」；此处保留字段是为
	// 让配置 schema 提前稳定（契约定死），I0 只实现 single 的行为。
	ModeTeam DeployMode = "team"
)

// 默认值。集中在此处，避免"安全默认"散落在多个文件里。
const (
	// DefaultListenAddr 默认仅监听回环地址。
	//
	// 依据 02 §11.3（D19 默认配置不安全）与 06 §5.1：
	// 本机其他进程（含恶意软件）不应能访问本地服务端口（07 §T5.1）。
	// 若要对外暴露，必须显式配置并在有 TLS 证书的前提下启动。
	DefaultListenAddr = "127.0.0.1"

	// DefaultListenPort 默认端口。
	DefaultListenPort = 7723

	// DefaultDataDirName 数据目录名（相对工作目录）。
	DefaultDataDirName = "data"

	// DefaultRetentionDays 默认日志保留天数（08 §6.2）。
	DefaultRetentionDays = 90
)

// 预置错误。调用方用 errors.Is 判定，不要字符串匹配（P-2 确定性优先）。
var (
	// ErrNoAuthorization 无授权凭证。
	//
	// 这是"拒绝启动"而不是"警告"：08 §1.1 硬约束 1 ——
	// 无凭证不启动。不是降级、不是"仅侦察模式"。是拒绝启动。
	ErrNoAuthorization = errors.New("config: authorization credential is required (see 08 §1.1: 无凭证不启动)")
)

// Config 是进程级配置。字段与 06 §5、08 §1 对齐。
type Config struct {
	// Deploy 部署模式。
	Deploy DeployMode `mapstructure:"deploy_mode"`

	// Server 网络与监听。
	Server ServerConfig `mapstructure:"server"`

	// Storage 存储路径。
	Storage StorageConfig `mapstructure:"storage"`

	// Authorization 授权凭证（08 §2）。
	//
	// 凭证内容本身不入 Config 结构体作长期存储：Path 指向 roe.yaml，
	// 由 core/scopekernel 在启动最早期读取并校验。此处只记路径与哈希。
	Authorization AuthorizationConfig `mapstructure:"authorization"`

	// PrivacyGateway 隐私网关开关（modules/M6 §4.2）。
	//
	// 注意 R7：Privacy Gateway 默认强制开启。此字段只能由配置文件显式
	// 置 false，且**不得**暴露任何 UI 开关（07 §T8、09 §R7）。
	// 禁用时启动日志必须高亮告警并写入审计（见 Validate）。
	PrivacyGateway PrivacyGatewayConfig `mapstructure:"privacy_gateway"`

	// Logging 日志配置。
	Logging LoggingConfig `mapstructure:"logging"`

	// DataHandling 数据处理要求（08 §6.3）。
	DataHandling DataHandlingConfig `mapstructure:"data_handling"`

	// Telemetry 遥测。
	//
	// D18：零遥测默认。Enabled 默认 false，且开启需显式 opt-in。
	// 本项目不实现任何向外部发送数据的代码路径；此字段仅为将来预留
	// 并在此显式记录"默认关闭"这一决策。
	Telemetry TelemetryConfig `mapstructure:"telemetry"`
}

// ServerConfig 监听与 TLS。
type ServerConfig struct {
	// Addr 监听地址。默认 127.0.0.1（安全默认，D19）。
	Addr string `mapstructure:"addr"`
	// Port 监听端口。
	Port int `mapstructure:"port"`
	// TLSCertFile / TLSKeyFile TLS 证书。
	//
	// 团队模式强制 TLS。若声明对外监听（Addr 非回环）但未提供证书，
	// 启动必须失败 —— 无证书时拒绝对外暴露而非自签降级（06 §5.2）。
	TLSCertFile string `mapstructure:"tls_cert_file"`
	TLSKeyFile  string `mapstructure:"tls_key_file"`

	// AccessTokenFile 一次性访问令牌文件（07 §T5.1）。
	//
	// 单机模式下启动时生成一次性令牌，防本机其他进程访问。
	// 令牌**不落普通日志**（07 §T5.1）。
	AccessTokenFile string `mapstructure:"access_token_file"`
}

// StorageConfig 存储路径。
type StorageConfig struct {
	// DataDir 数据根目录。
	DataDir string `mapstructure:"data_dir"`
	// EvidenceDir 原始工具输出的内容寻址存储（05 §2.1 RawOutputRef.storage_uri）。
	EvidenceDir string `mapstructure:"evidence_dir"`
	// LedgerFile 证据账本（append-only，05 §5.2）。
	LedgerFile string `mapstructure:"ledger_file"`
	// MapFile 心智地图（I4 实现；I0 只占位 schema）。
	MapFile string `mapstructure:"map_file"`
	// AuditLogFile 审计日志（append-only + 哈希链，08 §6.2）。
	AuditLogFile string `mapstructure:"audit_log_file"`
}

// AuthorizationConfig 授权凭证配置（08 §2）。
type AuthorizationConfig struct {
	// RoePath roe.yaml 路径。为空表示未提供凭证。
	RoePath string `mapstructure:"roe_path"`
	// Hash 凭证内容哈希。由启动时计算，只存哈希不存内容（08 §2 隐私约束）。
	Hash string `mapstructure:"-"`
}

// PrivacyGatewayConfig 隐私网关。
type PrivacyGatewayConfig struct {
	// Enabled 是否启用。默认 true（R7）。
	//
	// 只能通过配置文件显式置 false，不得有 UI 开关。
	Enabled *bool `mapstructure:"enabled"`
}

// LoggingConfig 日志配置。
type LoggingConfig struct {
	// Level 日志级别：debug / info / warn / error。
	Level string `mapstructure:"level"`
	// Format 输出格式：json / console。
	Format string `mapstructure:"format"`
	// File 日志文件路径。为空则只写 stderr。
	//
	// 注意：日志中只有 Privacy Gateway 的 token，不得出现真实 IP/凭据
	// （05 §3.2 凭据存储硬约束、modules/M6 §4.1）。
	File string `mapstructure:"file"`
}

// DataHandlingConfig 数据处理要求（08 §6.3）。
type DataHandlingConfig struct {
	// PIIHandling mask | allow。默认 mask。
	PIIHandling string `mapstructure:"pii_handling"`
	// RetentionDays 保留天数。默认 90（06 §6.2 / 08 §6.2）。
	RetentionDays int `mapstructure:"retention_days"`
	// NoExternalTransmission 禁止向外部传输目标相关数据。默认 true。
	NoExternalTransmission *bool `mapstructure:"no_external_transmission"`
}

// TelemetryConfig 遥测。默认关闭（D18）。
type TelemetryConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// Default 返回安全默认配置。
//
// 关键点：默认值是"最小权限 + 最小暴露"，不是"最方便"。
func Default() *Config {
	enabled := true
	noExt := true
	return &Config{
		Deploy: ModeSingle,
		Server: ServerConfig{
			Addr: DefaultListenAddr,
			Port: DefaultListenPort,
		},
		Storage:       StorageConfig{DataDir: DefaultDataDirName},
		Authorization: AuthorizationConfig{},
		PrivacyGateway: PrivacyGatewayConfig{
			Enabled: &enabled,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
		DataHandling: DataHandlingConfig{
			PIIHandling:            "mask",
			RetentionDays:          DefaultRetentionDays,
			NoExternalTransmission: &noExt,
		},
		Telemetry: TelemetryConfig{Enabled: false},
	}
}

// Load 从配置文件、环境变量、命令行默认值加载配置。
//
// 优先级（viper 语义）：显式 Set > 命令行 flag > 环境变量 > 配置文件 > 默认值。
//
// path 为空时不读文件，仅用默认值 + 环境变量。
func Load(path string) (*Config, error) {
	v := viper.New()

	cfg := Default()

	// 环境变量前缀 ALETH_。例如 ALETH_SERVER_ADDR。
	v.SetEnvPrefix("ALETH")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// 显式绑定默认值。viper 不会自动从结构体推断默认值，
	// 必须逐个 SetDefault，否则"安全默认"会被零值覆盖。
	setDefaults(v, cfg)

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			// 配置文件不存在是硬错误 —— 静默用默认值启动会让使用者
			// 误以为配置已生效（D19 的变体）。
			var notFound viper.ConfigFileNotFoundError
			if errors.As(err, &notFound) || os.IsNotExist(err) {
				return nil, fmt.Errorf("config: file %q not found: %w", path, err)
			}
			return nil, fmt.Errorf("config: parse %q: %w", path, err)
		}
	}

	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}

	return cfg, nil
}

func setDefaults(v *viper.Viper, cfg *Config) {
	v.SetDefault("deploy_mode", cfg.Deploy)

	v.SetDefault("server.addr", cfg.Server.Addr)
	v.SetDefault("server.port", cfg.Server.Port)
	v.SetDefault("server.tls_cert_file", cfg.Server.TLSCertFile)
	v.SetDefault("server.tls_key_file", cfg.Server.TLSKeyFile)
	v.SetDefault("server.access_token_file", cfg.Server.AccessTokenFile)

	v.SetDefault("storage.data_dir", cfg.Storage.DataDir)
	v.SetDefault("storage.evidence_dir", cfg.Storage.EvidenceDir)
	v.SetDefault("storage.ledger_file", cfg.Storage.LedgerFile)
	v.SetDefault("storage.map_file", cfg.Storage.MapFile)
	v.SetDefault("storage.audit_log_file", cfg.Storage.AuditLogFile)

	v.SetDefault("authorization.roe_path", cfg.Authorization.RoePath)

	// Privacy Gateway 默认开启（R7）。用指针区分"未配置"与"显式 false"。
	v.SetDefault("privacy_gateway.enabled", true)

	v.SetDefault("logging.level", cfg.Logging.Level)
	v.SetDefault("logging.format", cfg.Logging.Format)
	v.SetDefault("logging.file", cfg.Logging.File)

	v.SetDefault("data_handling.pii_handling", cfg.DataHandling.PIIHandling)
	v.SetDefault("data_handling.retention_days", cfg.DataHandling.RetentionDays)
	v.SetDefault("data_handling.no_external_transmission", true)

	v.SetDefault("telemetry.enabled", false)
}

// Validate 校验配置的自洽性。
//
// 依据 P-4（失败即熔断，不降级）：校验失败返回 error，调用方必须拒绝启动。
// 不做"警告后继续"。
func (c *Config) Validate() error {
	if err := c.validateServer(); err != nil {
		return err
	}
	if err := c.validateStorage(); err != nil {
		return err
	}
	if err := c.validateDataHandling(); err != nil {
		return err
	}
	if err := c.validateDeploy(); err != nil {
		return err
	}
	return nil
}

func (c *Config) validateServer() error {
	addr := strings.TrimSpace(c.Server.Addr)
	if addr == "" {
		return errors.New("config: server.addr is empty")
	}
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("config: server.port %d out of range [1,65535]", c.Server.Port)
	}

	// 判断是否对外监听。回环地址（127.0.0.0/8、::1）视为本机。
	if !isLoopback(addr) {
		// 对外监听必须有 TLS 证书 —— 无证书时拒绝对外暴露而非自签降级
		// （06 §5.2、02 §11.3 D19）。
		if c.Server.TLSCertFile == "" || c.Server.TLSKeyFile == "" {
			return fmt.Errorf(
				"config: listening on %s exposes the service beyond localhost; "+
					"TLS certificate is required (06 §5.2: 无证书时拒绝对外暴露而非自签降级)", addr)
		}
		if _, err := os.Stat(c.Server.TLSCertFile); err != nil {
			return fmt.Errorf("config: tls_cert_file %q: %w", c.Server.TLSCertFile, err)
		}
		if _, err := os.Stat(c.Server.TLSKeyFile); err != nil {
			return fmt.Errorf("config: tls_key_file %q: %w", c.Server.TLSKeyFile, err)
		}
	}
	return nil
}

func (c *Config) validateStorage() error {
	if strings.TrimSpace(c.Storage.DataDir) == "" {
		return errors.New("config: storage.data_dir is empty")
	}
	if err := validateRetention(c.DataHandling.RetentionDays); err != nil {
		return err
	}
	return nil
}

func (c *Config) validateDataHandling() error {
	switch c.DataHandling.PIIHandling {
	case "mask", "allow":
	default:
		return fmt.Errorf(
			"config: data_handling.pii_handling must be mask|allow, got %q (08 §6.3)", c.DataHandling.PIIHandling)
	}

	// pii_handling=allow 需额外授权说明（schemas/roe.schema.json）。
	// 这里不阻断，但在日志中留下痕迹（由 log 包处理）。
	if err := validateRetention(c.DataHandling.RetentionDays); err != nil {
		return err
	}
	return nil
}

func (c *Config) validateDeploy() error {
	switch c.Deploy {
	case ModeSingle, ModeTeam:
		return nil
	default:
		return fmt.Errorf("config: unknown deploy_mode %q (want single|team)", c.Deploy)
	}
}

func validateRetention(days int) error {
	if days < 1 || days > 3650 {
		return fmt.Errorf("config: retention_days %d out of range [1,3650] (schemas/roe.schema.json)", days)
	}
	return nil
}

// ListenAddr 返回完整的监听地址。
func (c *Config) ListenAddr() string {
	return net.JoinHostPort(c.Server.Addr, strconv.Itoa(c.Server.Port))
}

// IsLoopback 判断监听地址是否仅限本机。
func (c *Config) IsLoopback() bool {
	return isLoopback(c.Server.Addr)
}

// PrivacyGatewayEnabled 返回隐私网关是否启用。
//
// R7：默认 true。只有显式配置才能关闭，且关闭时调用方必须告警
// （见 cmd/alethd 的启动警告逻辑）。
func (c *Config) PrivacyGatewayEnabled() bool {
	if c.PrivacyGateway.Enabled == nil {
		return true
	}
	return *c.PrivacyGateway.Enabled
}

// ResolvePaths 把相对路径解析为绝对路径，并创建数据目录。
func (c *Config) ResolvePaths() error {
	dirs := []*string{
		&c.Storage.DataDir,
		&c.Storage.EvidenceDir,
	}
	for _, d := range dirs {
		if strings.TrimSpace(*d) == "" {
			continue
		}
		abs, err := filepath.Abs(*d)
		if err != nil {
			return fmt.Errorf("config: resolve %q: %w", *d, err)
		}
		*d = abs
		if err := os.MkdirAll(abs, 0o700); err != nil {
			return fmt.Errorf("config: mkdir %q: %w", abs, err)
		}
	}

	files := []*string{
		&c.Storage.LedgerFile,
		&c.Storage.MapFile,
		&c.Storage.AuditLogFile,
		&c.Logging.File,
	}
	for _, f := range files {
		if strings.TrimSpace(*f) == "" {
			continue
		}
		abs, err := filepath.Abs(*f)
		if err != nil {
			return fmt.Errorf("config: resolve %q: %w", *f, err)
		}
		// 确保父目录存在。
		if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
			return fmt.Errorf("config: mkdir parent of %q: %w", abs, err)
		}
		*f = abs
	}
	return nil
}

// DefaultFilePaths 给未显式配置的存储路径填上基于 DataDir 的默认值。
func (c *Config) DefaultFilePaths() {
	if c.Storage.EvidenceDir == "" {
		c.Storage.EvidenceDir = filepath.Join(c.Storage.DataDir, "evidence")
	}
	if c.Storage.LedgerFile == "" {
		c.Storage.LedgerFile = filepath.Join(c.Storage.DataDir, "ledger.db")
	}
	if c.Storage.MapFile == "" {
		c.Storage.MapFile = filepath.Join(c.Storage.DataDir, "map.db")
	}
	if c.Storage.AuditLogFile == "" {
		c.Storage.AuditLogFile = filepath.Join(c.Storage.DataDir, "audit.log")
	}
	if c.Logging.File == "" {
		c.Logging.File = filepath.Join(c.Storage.DataDir, "logs", "alethd.log")
	}
}

// RetentionDuration 返回日志保留时长。
func (c *Config) RetentionDuration() time.Duration {
	return time.Duration(c.DataHandling.RetentionDays) * 24 * time.Hour
}

func isLoopback(addr string) bool {
	if addr == "localhost" {
		return true
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		// 无法解析的地址按非回环处理（fail-closed：宁可要求 TLS，不放过）。
		return false
	}
	return ip.IsLoopback()
}
