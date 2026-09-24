package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecurityDefaults 验证"安全默认"（D19 / 02 §11.3 / 06 §5.1）。
//
// 这些断言是产品行为，不是测试细节：
//   - 默认仅监听 127.0.0.1（Q13 门禁的配置侧）
//   - Privacy Gateway 默认开启（R7）
//   - 零遥测默认（D18）
func TestSecurityDefaults(t *testing.T) {
	c := Default()

	if c.Server.Addr != DefaultListenAddr {
		t.Errorf("default listen addr = %q, want %q (D19: 默认仅监听 127.0.0.1)", c.Server.Addr, DefaultListenAddr)
	}
	if !c.IsLoopback() {
		t.Error("default config must be loopback-only")
	}
	if !c.PrivacyGatewayEnabled() {
		t.Error("Privacy Gateway must be enabled by default (09 R7)")
	}
	if c.Telemetry.Enabled {
		t.Error("telemetry must be disabled by default (D18)")
	}
	if c.DataHandling.PIIHandling != "mask" {
		t.Errorf("pii_handling = %q, want mask (08 §6.3)", c.DataHandling.PIIHandling)
	}
}

// TestNonLoopbackRequiresTLS 验证对外监听必须有 TLS 证书。
//
// 06 §5.2：强制 TLS；无证书时拒绝对外暴露而非自签降级。
func TestNonLoopbackRequiresTLS(t *testing.T) {
	c := Default()
	c.Server.Addr = "0.0.0.0"

	if err := c.Validate(); err == nil {
		t.Fatal("listening on 0.0.0.0 without TLS must fail validation")
	} else if !strings.Contains(err.Error(), "TLS") {
		t.Errorf("error should mention TLS, got: %v", err)
	}
}

// TestNonLoopbackWithTLSPasses 验证"对外监听 + 证书存在"是合法组合。
func TestNonLoopbackWithTLSPasses(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	for _, f := range []string{cert, key} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}

	c := Default()
	c.Server.Addr = "0.0.0.0"
	c.Server.TLSCertFile = cert
	c.Server.TLSKeyFile = key

	if err := c.Validate(); err != nil {
		t.Errorf("non-loopback with TLS certs should validate: %v", err)
	}
}

// TestUnparseableAddrIsTreatedAsNonLoopback 验证无法解析的地址按非回环处理。
//
// fail-closed 原则：宁可要求 TLS，不放过。
func TestUnparseableAddrIsTreatedAsNonLoopback(t *testing.T) {
	c := Default()
	c.Server.Addr = "not-an-ip"
	if c.IsLoopback() {
		t.Error("unparseable address must not be considered loopback (fail-closed)")
	}
	if err := c.Validate(); err == nil {
		t.Error("unparseable non-loopback addr without TLS must fail")
	}
}

func TestValidationRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"empty addr", func(c *Config) { c.Server.Addr = "" }},
		{"port 0", func(c *Config) { c.Server.Port = 0 }},
		{"port too high", func(c *Config) { c.Server.Port = 70000 }},
		{"bad pii_handling", func(c *Config) { c.DataHandling.PIIHandling = "share" }},
		{"zero retention", func(c *Config) { c.DataHandling.RetentionDays = 0 }},
		{"retention too long", func(c *Config) { c.DataHandling.RetentionDays = 99999 }},
		{"unknown deploy mode", func(c *Config) { c.Deploy = "cloud" }},
		{"empty data dir", func(c *Config) { c.Storage.DataDir = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			c.DefaultFilePaths()
			c.ResolvePaths() // 填绝对路径；空 data_dir 由下面重置
			tc.mutate(c)
			if err := c.Validate(); err == nil {
				t.Errorf("Validate must reject %s", tc.name)
			}
		})
	}
}

// TestPrivacyGatewayExplicitDisable 验证"显式关闭"这一路径确实存在
// （否则 R7 的告警逻辑是死代码），同时确认它只能来自配置。
func TestPrivacyGatewayExplicitDisable(t *testing.T) {
	c := Default()
	off := false
	c.PrivacyGateway.Enabled = &off
	if c.PrivacyGatewayEnabled() {
		t.Error("explicit disable must take effect")
	}
}

// TestLoadFromFile 验证配置文件可被读取并覆盖默认值。
func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alethd.yaml")
	body := `
server:
  addr: 127.0.0.1
  port: 9001
logging:
  level: debug
privacy_gateway:
  enabled: true
telemetry:
  enabled: false
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Server.Port != 9001 {
		t.Errorf("port = %d, want 9001 (config should override default)", c.Server.Port)
	}
	if c.Logging.Level != "debug" {
		t.Errorf("level = %q, want debug", c.Logging.Level)
	}
	if !c.PrivacyGatewayEnabled() {
		t.Error("privacy gateway must stay enabled")
	}
}

// TestLoadMissingFileFails 验证配置文件缺失是硬错误。
//
// 静默用默认值启动会让使用者误以为配置已生效（D19 的变体）。
func TestLoadMissingFileFails(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("missing config file must be an error")
	}
}

// TestLoadEnvOverride 验证环境变量可覆盖配置（ALETH_ 前缀）。
func TestLoadEnvOverride(t *testing.T) {
	t.Setenv("ALETH_SERVER_PORT", "9500")
	c, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Server.Port != 9500 {
		t.Errorf("port = %d, want 9500 from ALETH_SERVER_PORT", c.Server.Port)
	}
}

// TestDefaultFilePaths 验证未配置的路径由 data_dir 派生。
func TestDefaultFilePaths(t *testing.T) {
	c := Default()
	c.Storage.DataDir = "/tmp/aleth-data"
	c.DefaultFilePaths()

	wants := map[string]string{
		c.Storage.LedgerFile:   "/tmp/aleth-data/ledger.db",
		c.Storage.MapFile:      "/tmp/aleth-data/map.db",
		c.Storage.AuditLogFile: "/tmp/aleth-data/audit.log",
		c.Storage.EvidenceDir:  "/tmp/aleth-data/evidence",
	}
	for got, want := range wants {
		if filepath.ToSlash(got) != want {
			t.Errorf("path = %q, want %q", got, want)
		}
	}
}

func TestListenAddr(t *testing.T) {
	c := Default()
	c.Server.Addr = "127.0.0.1"
	c.Server.Port = 7723
	if got := c.ListenAddr(); got != "127.0.0.1:7723" {
		t.Errorf("ListenAddr = %q, want 127.0.0.1:7723", got)
	}
}

func TestRetentionDuration(t *testing.T) {
	c := Default()
	c.DataHandling.RetentionDays = 90
	if got := c.RetentionDuration().Hours(); got != 90*24 {
		t.Errorf("RetentionDuration = %v hours, want %d", got, 90*24)
	}
}
