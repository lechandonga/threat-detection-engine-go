// Package rule 定义检测规则、规则文件的严格校验与版本化加载。
package rule

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// 拒绝原因类型：非法规则、未知字段、重复标识等问题都能被区分。
const (
	ReasonUnknownField    = "unknown_field"
	ReasonDuplicateID     = "duplicate_rule_id"
	ReasonInvalidJSON     = "invalid_json"
	ReasonMissingField    = "missing_field"
	ReasonInvalidValue    = "invalid_value"
	ReasonInvalidOperator = "invalid_operator"
	ReasonFileProblem     = "file_problem"
)

// LoadError 描述规则加载失败的可区分原因。
type LoadError struct {
	Reason string // 见 Reason* 常量
	RuleID string // 涉及的规则标识，文件级问题可能为空
	Detail string
}

func (e *LoadError) Error() string {
	if e.RuleID != "" {
		return fmt.Sprintf("rule load rejected: reason=%s rule=%q: %s", e.Reason, e.RuleID, e.Detail)
	}
	return fmt.Sprintf("rule load rejected: reason=%s: %s", e.Reason, e.Detail)
}

// Condition 是规则的单条匹配条件（字段 + 操作符 + 期望值）。
type Condition struct {
	Field string      `json:"field"`
	Op    string      `json:"op"`
	Value interface{} `json:"value"`
}

// Rule 是一条关联检测规则的完整定义。
type Rule struct {
	ID          string      `json:"id"`
	Version     int         `json:"version"`
	Description string      `json:"description"`
	Match       []Condition `json:"match"`
	EntityField string      `json:"entity_field"`
	WindowMS    int64       `json:"window_ms"`
	SlideMS     int64       `json:"slide_ms,omitempty"` // 0 表示翻滚窗口
	Threshold   int         `json:"threshold"`
	SuppressMS  int64       `json:"suppress_ms"`
}

// File 是规则文件的整体结构。
type File struct {
	Rules []Rule `json:"rules"`
}

var validOps = map[string]bool{
	"eq": true, "ne": true, "in": true, "not_in": true,
	"gt": true, "gte": true, "lt": true, "lte": true,
	"contains": true, "prefix": true, "suffix": true, "regex": true, "exists": true,
}

var knownRuleFields = map[string]bool{
	"id": true, "version": true, "description": true, "match": true,
	"entity_field": true, "window_ms": true, "slide_ms": true,
	"threshold": true, "suppress_ms": true,
}

var knownCondFields = map[string]bool{"field": true, "op": true, "value": true}

// Parse 严格解析并校验规则文件的字节内容。
// 任何非法规则、未知字段或重复标识都会返回带明确 Reason 的错误。
func Parse(data []byte) (*File, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()

	var top map[string]json.RawMessage
	if err := dec.Decode(&top); err != nil {
		return nil, &LoadError{Reason: ReasonInvalidJSON, Detail: err.Error()}
	}
	if err := rejectUnknownFields(top, map[string]bool{"rules": true}, "$"); err != nil {
		return nil, err
	}
	rawRules, ok := top["rules"]
	if !ok {
		return nil, &LoadError{Reason: ReasonMissingField, Detail: `top-level "rules" is required`}
	}

	var raws []map[string]json.RawMessage
	if err := json.Unmarshal(rawRules, &raws); err != nil {
		return nil, &LoadError{Reason: ReasonInvalidJSON, Detail: `"rules" must be an array of rule objects: ` + err.Error()}
	}

	seen := make(map[string]bool, len(raws))
	f := &File{Rules: make([]Rule, 0, len(raws))}
	for i, raw := range raws {
		rid := string(raw["id"])
		if rid == "" {
			rid = fmt.Sprintf("<rules[%d]>", i)
		}
		reject := func(reason, detail string) error {
			id := strings.Trim(rid, `"`)
			return &LoadError{Reason: reason, RuleID: id, Detail: detail}
		}
		if err := rejectUnknownFields(raw, knownRuleFields, "rule"); err != nil {
			err.(*LoadError).RuleID = strings.Trim(rid, `"`)
			return nil, err
		}
		var r Rule
		if err := json.Unmarshal(mustMarshal(raw), &r); err != nil {
			return nil, reject(ReasonInvalidJSON, err.Error())
		}
		if r.ID == "" {
			return nil, reject(ReasonMissingField, `"id" must be a non-empty string`)
		}
		if seen[r.ID] {
			return nil, reject(ReasonDuplicateID, "rule id appears more than once in the file")
		}
		seen[r.ID] = true
		if err := validateRule(&r); err != nil {
			return nil, err
		}
		f.Rules = append(f.Rules, r)
	}

	sort.SliceStable(f.Rules, func(i, j int) bool { return f.Rules[i].ID < f.Rules[j].ID })
	return f, nil
}

func validateRule(r *Rule) error {
	reject := func(reason, detail string) error {
		return &LoadError{Reason: reason, RuleID: r.ID, Detail: detail}
	}
	if r.Version < 1 {
		return reject(ReasonInvalidValue, `"version" must be >= 1`)
	}
	if len(r.Match) == 0 {
		return reject(ReasonMissingField, `"match" must contain at least one condition`)
	}
	if r.EntityField == "" {
		return reject(ReasonMissingField, `"entity_field" must name the entity (e.g. src_ip)`)
	}
	if r.WindowMS <= 0 {
		return reject(ReasonInvalidValue, `"window_ms" must be > 0`)
	}
	if r.SlideMS < 0 || (r.SlideMS > 0 && r.SlideMS > r.WindowMS) {
		return reject(ReasonInvalidValue, `"slide_ms" must be 0 (tumbling) or <= window_ms`)
	}
	if r.SlideMS > 0 && r.WindowMS%r.SlideMS != 0 {
		return reject(ReasonInvalidValue, `window_ms must be divisible by slide_ms`)
	}
	if r.Threshold < 1 {
		return reject(ReasonInvalidValue, `"threshold" must be >= 1`)
	}
	if r.SuppressMS <= 0 {
		return reject(ReasonInvalidValue, `"suppress_ms" must be > 0`)
	}
	for i, c := range r.Match {
		if c.Field == "" {
			return reject(ReasonMissingField, fmt.Sprintf("match[%d].field is empty", i))
		}
		if !validOps[c.Op] {
			return reject(ReasonInvalidOperator, fmt.Sprintf("match[%d].op %q is not supported", i, c.Op))
		}
		if c.Op != "exists" && c.Value == nil {
			return reject(ReasonMissingField, fmt.Sprintf("match[%d].value is required for op %q", i, c.Op))
		}
		switch c.Op {
		case "in", "not_in":
			if _, ok := c.Value.([]interface{}); !ok {
				return reject(ReasonInvalidValue, fmt.Sprintf("match[%d]: op %q needs an array value", i, c.Op))
			}
		case "regex":
			s, ok := c.Value.(string)
			if !ok {
				return reject(ReasonInvalidValue, fmt.Sprintf("match[%d]: regex value must be a string", i))
			}
			if _, err := regexp.Compile(s); err != nil {
				return reject(ReasonInvalidValue, fmt.Sprintf("match[%d]: invalid regex: %v", i, err))
			}
		}
	}
	return nil
}

func rejectUnknownFields(obj map[string]json.RawMessage, known map[string]bool, where string) error {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !known[k] {
			return &LoadError{Reason: ReasonUnknownField, Detail: fmt.Sprintf("unknown field %q in %s", k, where)}
		}
	}
	return nil
}

func mustMarshal(m map[string]json.RawMessage) []byte {
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

// ConditionFields 暴露给引擎，用于编译后的匹配器。
func (r *Rule) ConditionFields() []Condition { return r.Match }
