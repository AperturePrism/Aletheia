// Package nmap 是 nmap 的参数化适配器与确定性解析器（modules/M1 T1.2）。
//
// 输出格式选 XML（-oX 到 stdout）：结构化解析替代正则硬凑（09 §7 陷阱
// 「解析用正则硬凑」），XML 破损时整体 fail-closed 而不是猜测半份结果。
// 行号追溯用 xml.Decoder 的 InputOffset 映射到物理行 —— 实体草稿的
// source_line 回指原始输出行号（05 §2.1）。
//
// M1 §4.3 的三个翻车点在此显式处理：
//   - 版本串前导数字守卫（service name/version 匹配 ^\d+\s*\( 时拒绝采信）
//   - ANSI 污染（解析前统一 strip，见 spectrum.Normalize）
//   - Schema 参数名不匹配（未知参数显式 INVALID_ARGUMENT，见 ingest.ParamSchema）
package nmap

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"github.com/AperturePrism/aleth/core/ingest"
	"github.com/AperturePrism/aleth/core/spectrum"
)

// supported 区间：XML 输出结构（-oX）自 7.40 起稳定；上限只声明到当前
// 已验证的主版本。超出区间的版本 fail-closed（TOOL_VERSION_MISMATCH）。
var supported = ingest.VersionRange{Min: "7.40", Max: "7.99"}

// safeScripts 是 --script 的白名单（M1 §4.2：枚举类参数必须有白名单）。
// 刻意只收录「信息收集类、无主动利用行为」的脚本；扩名单属于安全决策，需 review。
var safeScripts = []string{"default", "http-title", "http-headers", "ssl-cert", "ftp-anon"}

// versionTrap 是 M1 §4.3 翻车点 1 的守卫：nmap 会输出 "2 (RPC #100000)"
// 这类 rpc 程序号片段，若当作产品版本传递给下游利用框架就是真实事故
// （调研缺陷 D9 的原始案例）。
var versionTrap = regexp.MustCompile(`^\d+\s*\(`)

// NewAdapter 返回 nmap 适配器。
func NewAdapter() ingest.Adapter {
	return &ingest.BaseAdapter{
		ToolName: "nmap",
		Versions: supported,
		SchemaDef: &ingest.ParamSchema{
			Params: []ingest.ParamDef{
				{Name: "target", Type: ingest.ParamTarget, Required: true, ScopeChecked: true,
					Aliases: []string{"host", "hosts"}},
				{Name: "ports", Type: ingest.ParamPortRange, ArgFlag: "-p"},
				{Name: "timing", Type: ingest.ParamEnum, Choices: []string{"T2", "T3", "T4"}, ArgFlag: "-T"},
				{Name: "scripts", Type: ingest.ParamEnumList, Choices: safeScripts, ArgFlag: "--script"},
				{Name: "service_detection", Type: ingest.ParamBoolFlag, ArgFlag: "-sV",
					Aliases: []string{"sV"}},
				{Name: "no_ping", Type: ingest.ParamBoolFlag, ArgFlag: "-Pn",
					Aliases: []string{"Pn"}},
			},
		},
		// -oX - 让 nmap 把 XML 写到 stdout：stdout 全部进入解析器，
		// 不存在「stderr 里的第二份真相」旁路（threat-model T2.3 输出统一管道）。
		StaticArgs: []string{"-oX", "-"},
		ParseFn:    parse,
		Fold:       ingest.FoldStrategy{},
	}
}

// ---- XML 结构（只映射我们消费的字段）----

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus     `xml:"status"`
	Addresses []nmapAddress  `xml:"address"`
	Hostnames []nmapHostname `xml:"hostnames>hostname"`
	Ports     []nmapPort     `xml:"ports>port"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPort struct {
	Protocol string        `xml:"protocol,attr"`
	PortID   string        `xml:"portid,attr"`
	State    nmapPortState `xml:"state"`
	Service  nmapService   `xml:"service"`
}

type nmapPortState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// parse 是纯函数：相同输入必得相同光谱（Q6）。
//
// 行号口径：清洗（UTF-8 消毒 + ANSI strip）不产生或删除换行，因此对清洗后
// 字节建立的行号与原始输出行号一致 —— SpectrumLine/EntityDraft 的行号
// 直接可用于回看原始证据文件。
func parse(raw []byte, execID string) (*alethv1.EvidenceSpectrum, error) {
	// 空输出（M1 §6 边界用例）：nmap 的正常结束一定带完整 XML（含 runstats），
	// 空 stdout 视为「没有观察到任何内容」—— 合法观测，显式记 warning。
	if len(raw) == 0 {
		return &alethv1.EvidenceSpectrum{
			ExecId:  execID,
			Quality: ingest.Quality(0, 0, []string{"empty tool output"}),
		}, nil
	}
	sanitized, fixedUTF8 := spectrum.SanitizeUTF8(raw)
	clean := spectrum.CleanANSI(sanitized)
	var warnings []string
	if fixedUTF8 {
		warnings = append(warnings, "input contained invalid UTF-8 bytes; replaced with U+FFFD")
	}
	table := ingest.LineStartTable(clean)

	lineOf := func(off int64) uint32 { return ingest.LineAt(table, off) }

	// 第一遍：token 流校验 + 记录元素行号（文档序）。
	addrLines := [][]uint32{} // 每 host 的 address 元素行号列表
	portLines := []uint32{}   // 全部 port 元素行号（全局文档序）
	hostIdx := -1
	d := xml.NewDecoder(bytes.NewReader(clean))
	for {
		off := d.InputOffset()
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// XML 破损 → fail-closed：半份主机清单比完整失败更危险（05 §0 C2）。
			return nil, fmt.Errorf("nmap xml broken at line %d: %w", lineOf(off), err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "host":
			hostIdx++
			addrLines = append(addrLines, nil)
		case "address":
			if hostIdx >= 0 {
				addrLines[hostIdx] = append(addrLines[hostIdx], lineOf(off))
			}
		case "port":
			portLines = append(portLines, lineOf(off))
		}
	}

	// 第二遍：结构化解码。
	var run nmapRun
	if err := xml.Unmarshal(clean, &run); err != nil {
		return nil, fmt.Errorf("nmap xml unmarshal: %w", err)
	}

	var recs []spectrum.Record
	var entities []*alethv1.EntityDraft
	var entitiesTotal int

	portIdx := 0
	for hi := range run.Hosts {
		h := &run.Hosts[hi]
		var addr string
		addrLine := uint32(1)
		for ai, a := range h.Addresses {
			if a.AddrType == "ipv4" && addr == "" {
				addr = a.Addr
				if ai < len(addrLines[hi]) {
					addrLine = addrLines[hi][ai]
				}
			}
		}
		if addr != "" {
			entities = append(entities, &alethv1.EntityDraft{
				Kind: alethv1.EntityKind_ASSET,
				Attributes: map[string]string{
					"addr": addr,
				},
				SourceLine:       addrLine,
				ParserConfidence: 1.0,
			})
			recs = append(recs, spectrum.Record{
				OrigLineStart: addrLine, OrigLineEnd: addrLine,
				Template:  "host {addr} {state}",
				Vars:      map[string]string{"addr": addr, "state": orDefault(h.Status.State, "unknown")},
				FoldCount: 1,
			})
		} else if h.Status.State == "up" {
			warnings = append(warnings, "up host without ipv4 address; entity draft skipped")
		}

		for pi := range h.Ports {
			p := &h.Ports[pi]
			line := uint32(1)
			if portIdx < len(portLines) {
				line = portLines[portIdx]
			}
			portIdx++

			vars := map[string]string{
				"port":     p.PortID,
				"protocol": p.Protocol,
				"state":    orDefault(p.State.State, "unknown"),
				"service":  p.Service.Name,
			}
			svcAttrs := map[string]string{
				"port":     p.PortID,
				"protocol": p.Protocol,
			}
			confidence := 1.0
			trapWarned := false
			// 前导数字守卫逐字段执行：命中的字段拒绝采信（M1 §4.3），
			// 未命中的字段保留。Record（vars）始终保留原始观测值 ——
			// 无损层不丢数据；实体草稿才是「采信与否」的裁决点。
			if n := p.Service.Name; n != "" {
				if versionTrap.MatchString(n) {
					trapWarned = true
				} else {
					svcAttrs["service_name"] = n
				}
			}
			if prod := p.Service.Product; prod != "" {
				if versionTrap.MatchString(prod) {
					trapWarned = true
				} else {
					svcAttrs["product"] = prod
				}
			}
			if ver := p.Service.Version; ver != "" {
				if versionTrap.MatchString(ver) {
					trapWarned = true
				} else {
					svcAttrs["version"] = ver
				}
			}
			if trapWarned {
				warnings = append(warnings,
					"leading-number version trap hit; matching service fields rejected: ^\\d+\\s*\\(")
				confidence = 0.5
			}
			if addr != "" {
				svcAttrs["host_addr"] = addr
			}
			recs = append(recs, spectrum.Record{
				OrigLineStart: line, OrigLineEnd: line,
				Template:  "port {port}/{protocol} {state} {service}",
				Vars:      vars,
				FoldCount: 1,
			})
			if addr != "" {
				entities = append(entities, &alethv1.EntityDraft{
					Kind:             alethv1.EntityKind_SERVICE,
					Attributes:       svcAttrs,
					SourceLine:       line,
					ParserConfidence: confidence,
				})
			}
		}
	}
	entitiesTotal = len(entities)

	folded := spectrum.Fold(recs)
	return &alethv1.EvidenceSpectrum{
		ExecId:   execID,
		Lines:    spectrum.RecordsToLines(folded),
		Entities: entities,
		Quality:  ingest.Quality(entitiesTotal, 0, warnings),
	}, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
