package rules

import (
	"errors"
	"strings"
	"testing"
)

func mustRule(id string) string {
	return `{
		"id": "` + id + `",
		"version": 1,
		"name": "test rule ` + id + `",
		"severity": "high",
		"event_type": "login_failed",
		"window_seconds": 300,
		"threshold": 3,
		"suppress_seconds": 60
	}`
}

func TestParseValidRuleSet(t *testing.T) {
	t.Log("业务: 规则加载 —— 合法规则文件应完整加载并按 ID 索引")
	set, err := Parse([]byte(`{"rules": [` + mustRule("R-002") + `,` + mustRule("R-001") + `]}`))
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("expected 2 rules, got %d", set.Len())
	}
	if set.All()[0].ID != "R-001" {
		t.Fatalf("rules should be sorted by ID, got %s first", set.All()[0].ID)
	}
	if _, ok := set.ByID("R-002"); !ok {
		t.Fatal("R-002 should be indexed by ID")
	}
	t.Logf("用例通过: 加载 %d 条规则, 首条=%s", set.Len(), set.All()[0].ID)
}

func TestParseRejectsDuplicateID(t *testing.T) {
	t.Log("业务: 规则校验 —— 重复规则 ID 必须被拒绝且原因可区分")
	_, err := Parse([]byte(`{"rules": [` + mustRule("R-001") + `,` + mustRule("R-001") + `]}`))
	var le *LoadError
	if !errors.As(err, &le) {
		t.Fatalf("expected LoadError, got %v", err)
	}
	if !le.HasCode(ReasonDuplicateID) {
		t.Fatalf("expected DUPLICATE_ID rejection, got %v", le.Rejections)
	}
	t.Logf("用例通过: 拒绝原因=%v", le.Rejections[0])
}

func TestParseRejectsUnknownField(t *testing.T) {
	t.Log("业务: 规则校验 —— 未知字段不得静默跳过")
	rule := strings.Replace(mustRule("R-001"), `"version": 1`, `"version": 1, "threashold": 3`, 1)
	_, err := Parse([]byte(`{"rules": [` + rule + `]}`))
	var le *LoadError
	if !errors.As(err, &le) || !le.HasCode(ReasonUnknownField) {
		t.Fatalf("expected UNKNOWN_FIELD rejection, got %v", err)
	}
	for _, r := range le.Rejections {
		if r.Field == "threashold" {
			t.Logf("用例通过: 精确定位未知字段 %q (%s)", r.Field, r.Code)
			return
		}
	}
	t.Fatalf("expected rejection to name the unknown field, got %v", le.Rejections)
}

func TestParseRejectsInvalidValues(t *testing.T) {
	t.Log("业务: 规则校验 —— 非法字段取值需逐条报告")
	cases := map[string]string{
		"空规则ID":   strings.Replace(mustRule("R-001"), `"id": "R-001"`, `"id": ""`, 1),
		"零阈值":     strings.Replace(mustRule("R-001"), `"threshold": 3`, `"threshold": 0`, 1),
		"负窗口":     strings.Replace(mustRule("R-001"), `"window_seconds": 300`, `"window_seconds": -5`, 1),
		"非法严重级别": strings.Replace(mustRule("R-001"), `"severity": "high"`, `"severity": "urgent"`, 1),
	}
	for name, rule := range cases {
		_, err := Parse([]byte(`{"rules": [` + rule + `]}`))
		var le *LoadError
		if !errors.As(err, &le) || !le.HasCode(ReasonInvalidField) {
			t.Fatalf("%s: expected INVALID_FIELD rejection, got %v", name, err)
		}
		t.Logf("用例通过: %s -> %v", name, le.Rejections[0])
	}
}

func TestParseRejectsBrokenJSON(t *testing.T) {
	t.Log("业务: 规则校验 —— 文件级 JSON 错误需与规则级错误区分")
	_, err := Parse([]byte(`{"rules": [`))
	var le *LoadError
	if !errors.As(err, &le) || !le.HasCode(ReasonInvalidJSON) {
		t.Fatalf("expected INVALID_JSON rejection, got %v", err)
	}
	t.Logf("用例通过: %v", le.Rejections[0])
}

func TestReloadIsAtomicAndKeepsOldOnFailure(t *testing.T) {
	t.Log("业务: 规则热更新 —— 原子生效, 失败时保留旧规则, 不得新旧混用")
	old, err := Parse([]byte(`{"rules": [` + mustRule("R-001") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	loader := NewLoader(old)

	good := strings.Replace(mustRule("R-001"), `"version": 1`, `"version": 2`, 1)
	if _, err := loader.ReloadReader(strings.NewReader(`{"rules": [` + good + `]}`)); err != nil {
		t.Fatalf("valid reload should succeed: %v", err)
	}
	if r, _ := loader.Current().ByID("R-001"); r.Version != 2 {
		t.Fatalf("expected version 2 after reload, got %d", r.Version)
	}
	t.Log("用例通过: 合法新规则整体生效 (version 1 -> 2)")

	bad := strings.Replace(mustRule("R-001"), `"version": 1`, `"version": 3, "bogus": true`, 1)
	if _, err := loader.ReloadReader(strings.NewReader(`{"rules": [` + bad + `]}`)); err == nil {
		t.Fatal("invalid reload should fail")
	}
	cur := loader.Current()
	if cur.Len() != 1 {
		t.Fatalf("old rule set must stay intact, got %d rules", cur.Len())
	}
	if r, _ := cur.ByID("R-001"); r.Version != 2 {
		t.Fatalf("failed reload must keep old rules, got version %d", r.Version)
	}
	t.Log("用例通过: 非法新规则被整体拒绝, 旧规则(version 2)继续生效")
}
