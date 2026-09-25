// Package nuclei 是 projectdiscovery nuclei 的参数化适配器与确定性解析器
// （modules/M1 T1.4）。
//
// 输出格式选 JSONL（-json，v3 起 kebab-case 字段）。nuclei 的产出是
// 「模板匹配结果」，在 Aletheia 里它只是**观测**：L0 不判定漏洞（M1 §2.2 N1），
// matcher-status=false 的行同样保留为观测记录，DEFECT 草稿的状态如实标注。
//
// 抽取目标（05 §3.1）：DEFECT（defect_type=template-id / status / severity）。
package nuclei

import (
	"encoding/json"
	"fmt"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"github.com/AperturePrism/aleth/core/ingest"
	"github.com/AperturePrism/aleth/core/spectrum"
)

// supported：v3 的 -jsonl 输出结构自 3.0 起稳定。
var supported = ingest.VersionRange{Min: "3.0.0", Max: "3.99.99"}

// severityChoices 是 nuclei 严重级别白名单（枚举参数必须有白名单，M1 §4.2）。
var severityChoices = []string{"info", "low", "medium", "high", "critical"}

// NewAdapter 返回 nuclei 适配器。
func NewAdapter() ingest.Adapter {
	return &ingest.BaseAdapter{
		ToolName: "nuclei",
		Versions: supported,
		SchemaDef: &ingest.ParamSchema{
			Params: []ingest.ParamDef{
				{Name: "target", Type: ingest.ParamTarget, Required: true, ScopeChecked: true,
					Aliases: []string{"host", "url"}},
				{Name: "severity", Type: ingest.ParamEnumList, Choices: severityChoices,
					ArgFlag: "-severity"},
				{Name: "templates", Type: ingest.ParamPath, ArgFlag: "-t"},
				{Name: "rate_limit", Type: ingest.ParamEnum, Choices: []string{"50", "100", "150"},
					ArgFlag: "-rl"},
			},
		},
		StaticArgs: []string{"-jsonl", "-nc", "-silent"},
		ParseFn:    parse,
		Fold:       ingest.FoldStrategy{},
	}
}

type nucleiClassification struct {
	CVEID []string `json:"cve-id"`
}

type nucleiInfo struct {
	Name           string                `json:"name"`
	Severity       string                `json:"severity"`
	Tags           []string              `json:"tags"`
	Classification *nucleiClassification `json:"classification"`
}

type nucleiLine struct {
	TemplateID    string     `json:"template-id"`
	Info          nucleiInfo `json:"info"`
	MatcherStatus bool       `json:"matcher-status"`
	MatchedAt     string     `json:"matched-at"`
	Host          string     `json:"host"`
	Type          string     `json:"type"`
	CVE           []string   `json:"cve"`
	Extracted     []string   `json:"extracted-results"`
	Timestamp     string     `json:"timestamp"`
}

func parse(raw []byte, execID string) (*alethv1.EvidenceSpectrum, error) {
	lines, warnings := spectrum.Normalize(raw, 0)

	var recs []spectrum.Record
	var entities []*alethv1.EntityDraft
	var unparsed int
	lineNo := 0
	total := 0

	for _, text := range lines {
		lineNo++
		if text == "" {
			continue
		}
		total++
		var obj nucleiLine
		if err := json.Unmarshal([]byte(text), &obj); err != nil {
			unparsed++
			warnings = append(warnings, fmt.Sprintf("line %d: not valid JSONL (%v)", lineNo, err))
			recs = append(recs, ingest.RawRecord(uint32(lineNo), text))
			continue
		}
		status := "unmatched"
		if obj.MatcherStatus {
			status = "matched"
		}
		recs = append(recs, spectrum.Record{
			OrigLineStart: uint32(lineNo), OrigLineEnd: uint32(lineNo),
			Template: "finding {id} {severity} {status} {matched}",
			Vars: map[string]string{
				"id":       obj.TemplateID,
				"severity": obj.Info.Severity,
				"status":   status,
				"matched":  obj.MatchedAt,
			},
			FoldCount: 1,
		})
		if !obj.MatcherStatus {
			continue // 未匹配：保留观测，不产出 DEFECT 草稿
		}
		attrs := map[string]string{
			"defect_type": obj.TemplateID,
			"status":      status,
		}
		if obj.Info.Severity != "" {
			attrs["severity"] = obj.Info.Severity
		}
		if obj.MatchedAt != "" {
			attrs["matched_url"] = obj.MatchedAt
		}
		cves := obj.CVE
		if len(cves) == 0 && obj.Info.Classification != nil {
			cves = obj.Info.Classification.CVEID
		}
		if len(cves) > 0 {
			attrs["cve"] = cves[0]
		}
		entities = append(entities, &alethv1.EntityDraft{
			Kind:             alethv1.EntityKind_DEFECT,
			Attributes:       attrs,
			SourceLine:       uint32(lineNo),
			ParserConfidence: 1.0,
		})
	}

	folded := spectrum.Fold(recs)
	return &alethv1.EvidenceSpectrum{
		ExecId:   execID,
		Lines:    spectrum.RecordsToLines(folded),
		Entities: entities,
		Quality:  ingest.Quality(total, unparsed, warnings),
	}, nil
}
