// roe.yaml 的 Scope 段解析（08 §3 语法 → scopekernel.Scope）。
//
// roe.schema.json（冻结）是权威语法；解析在此处做第二次校验
// （schema 管 JSON 结构，这里管语义：CIDR 合法性、规则非空、默认拒绝策略）。
package scopekernel

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type scopeRuleYAML struct {
	CIDR      string `yaml:"cidr"`
	Host      string `yaml:"host"`
	Ports     []any  `yaml:"ports"`
	URLPrefix string `yaml:"url_prefix"`
}

type scopeYAML struct {
	Targets struct {
		Include []scopeRuleYAML `yaml:"include"`
		Exclude []scopeRuleYAML `yaml:"exclude"`
	} `yaml:"targets"`
}

// ParseScopeFile 从 roe.yaml 文件解析 Scope（LoadScope 用）。
// 空的 include 列表是配置错误：默认拒绝策略下它意味着"什么都不允许"，
// 与"无凭证拒绝启动"（08 §1.1）同级 —— fail-closed。
func ParseScopeFile(path string) (Scope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Scope{}, fmt.Errorf("read roe file: %w", err)
	}
	return ParseScope(raw)
}

// ParseScope 从 YAML 字节解析 Scope。
func ParseScope(raw []byte) (Scope, error) {
	var y scopeYAML
	if err := yaml.Unmarshal(raw, &y); err != nil {
		return Scope{}, fmt.Errorf("parse roe yaml: %w", err)
	}
	var scope Scope
	for _, r := range y.Targets.Include {
		rule, err := buildRule(r)
		if err != nil {
			return Scope{}, fmt.Errorf("include rule: %w", err)
		}
		scope.Include = append(scope.Include, rule)
	}
	for _, r := range y.Targets.Exclude {
		rule, err := buildRule(r)
		if err != nil {
			return Scope{}, fmt.Errorf("exclude rule: %w", err)
		}
		scope.Exclude = append(scope.Exclude, rule)
	}
	if len(scope.Include) == 0 {
		return Scope{}, fmt.Errorf("scope has no include targets (08 §1.1: 至少一个 include 目标)")
	}
	return scope, nil
}

func buildRule(r scopeRuleYAML) (TargetRule, error) {
	switch {
	case strings.TrimSpace(r.CIDR) != "":
		return NewCIDRRule(r.CIDR)
	case strings.TrimSpace(r.Host) != "":
		host, err := NormalizeTarget(r.Host)
		if err != nil {
			return TargetRule{}, fmt.Errorf("host %q: %w", r.Host, err)
		}
		rule := TargetRule{Kind: "host", Value: r.Host, Host: host}
		for _, p := range r.Ports {
			var n int
			switch v := p.(type) {
			case int:
				n = v
			case string:
				n, _ = strconv.Atoi(v)
			default:
				return TargetRule{}, fmt.Errorf("port must be int, got %T", p)
			}
			if n <= 0 || n > 65535 {
				return TargetRule{}, fmt.Errorf("port %d out of range", n)
			}
			rule.Ports = append(rule.Ports, uint16(n))
		}
		return rule, nil
	case strings.TrimSpace(r.URLPrefix) != "":
		host, err := NormalizeTarget(r.URLPrefix)
		if err != nil {
			return TargetRule{}, fmt.Errorf("url_prefix %q: %w", r.URLPrefix, err)
		}
		return TargetRule{Kind: "url_prefix", Value: r.URLPrefix, Host: host}, nil
	default:
		return TargetRule{}, fmt.Errorf("rule must have one of cidr/host/url_prefix")
	}
}
