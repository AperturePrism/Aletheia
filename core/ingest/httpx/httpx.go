// Package httpx 是 projectdiscovery httpx 的参数化适配器与确定性解析器
// （modules/M1 T1.3）。
//
// 输出格式选 JSONL（-json）：每行一个独立 JSON 对象，单行破损只降级该行
// （RAW 记录 + unparsed 计数 + warning），不影响其余行 —— 逐行格式的部分
// 解析是显式的、可审计的，与 XML 的整体 fail-closed 形成对照。
//
// 抽取目标（05 §3.1）：ENDPOINT（url/method/status_code）、ASSET（A 记录地址）。
package httpx

import (
	"encoding/json"
	"fmt"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"github.com/AperturePrism/aleth/core/ingest"
	"github.com/AperturePrism/aleth/core/spectrum"
)

// supported：-json 输出字段（snake_case）在 1.3–1.6 间保持兼容。
var supported = ingest.VersionRange{Min: "1.3.0", Max: "1.6.99"}

// NewAdapter 返回 httpx 适配器。
func NewAdapter() ingest.Adapter {
	return &ingest.BaseAdapter{
		ToolName: "httpx",
		Versions: supported,
		SchemaDef: &ingest.ParamSchema{
			Params: []ingest.ParamDef{
				{Name: "target", Type: ingest.ParamTarget, Required: true, ScopeChecked: true,
					Aliases: []string{"host", "url"}},
				{Name: "ports", Type: ingest.ParamPortRange, ArgFlag: "-p"},
				{Name: "tech_detect", Type: ingest.ParamBoolFlag, ArgFlag: "-td",
					Aliases: []string{"td"}},
				{Name: "follow_redirects", Type: ingest.ParamBoolFlag, ArgFlag: "-fr"},
				{Name: "threads", Type: ingest.ParamEnum, Choices: []string{"10", "25", "50"},
					ArgFlag: "-c"},
			},
		},
		// -json / -silent / -no-color 是解析正确性与确定性输出的前提，
		// 由适配器固定加入，调用方不可改写（Schema 里没有对应参数）。
		StaticArgs: []string{"-json", "-silent", "-no-color"},
		ParseFn:    parse,
		Fold:       ingest.FoldStrategy{},
	}
}

// httpxLine 映射 -json 输出中我们消费的字段（缺失容错）。
type httpxLine struct {
	URL           string   `json:"url"`
	Input         string   `json:"input"`
	Method        string   `json:"method"`
	Failed        bool     `json:"failed"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title"`
	Webserver     string   `json:"webserver"`
	Tech          []string `json:"tech"`
	Scheme        string   `json:"scheme"`
	ARecords      []string `json:"a"`
	ResponseTime  string   `json:"response_time"`
	ContentLength int      `json:"content_length"`
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
			continue // 空行不计入有效行分母
		}
		total++
		var obj httpxLine
		if err := json.Unmarshal([]byte(text), &obj); err != nil {
			unparsed++
			warnings = append(warnings, fmt.Sprintf("line %d: not valid JSONL (%v)", lineNo, err))
			recs = append(recs, ingest.RawRecord(uint32(lineNo), text))
			continue
		}
		if obj.Failed {
			// 探测失败的主机是有效观测（不是解析失败），保留为行记录。
			recs = append(recs, spectrum.Record{
				OrigLineStart: uint32(lineNo), OrigLineEnd: uint32(lineNo),
				Template:  "probe {input} failed",
				Vars:      map[string]string{"input": obj.Input},
				FoldCount: 1,
			})
			continue
		}
		method := obj.Method
		confidence := 1.0
		if method == "" {
			// httpx 仅在 GET 探测时可能省略 method 字段；缺省值必须显式声明。
			method = "GET"
			warnings = append(warnings, fmt.Sprintf("line %d: method absent, defaulted to GET", lineNo))
			confidence = 0.8
		}
		recs = append(recs, spectrum.Record{
			OrigLineStart: uint32(lineNo), OrigLineEnd: uint32(lineNo),
			Template: "endpoint {method} {url} {status}",
			Vars: map[string]string{
				"method": method,
				"url":    obj.URL,
				"status": fmt.Sprintf("%d", obj.StatusCode),
			},
			FoldCount: 1,
		})
		entities = append(entities, &alethv1.EntityDraft{
			Kind: alethv1.EntityKind_ENDPOINT,
			Attributes: map[string]string{
				"url":         obj.URL,
				"method":      method,
				"status_code": fmt.Sprintf("%d", obj.StatusCode),
			},
			SourceLine:       uint32(lineNo),
			ParserConfidence: confidence,
		})
		if len(obj.ARecords) > 0 && obj.ARecords[0] != "" {
			entities = append(entities, &alethv1.EntityDraft{
				Kind: alethv1.EntityKind_ASSET,
				Attributes: map[string]string{
					"addr": obj.ARecords[0],
				},
				SourceLine:       uint32(lineNo),
				ParserConfidence: confidence,
			})
		}
	}

	folded := spectrum.Fold(recs)
	return &alethv1.EvidenceSpectrum{
		ExecId:   execID,
		Lines:    spectrum.RecordsToLines(folded),
		Entities: entities,
		Quality:  ingest.Quality(total, unparsed, warnings),
	}, nil
}
