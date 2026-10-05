package engine

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/threat-detection-engine-go/internal/rules"
)

var base = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func testLoader(t *testing.T, ruleJSON string) *rules.Loader {
	t.Helper()
	set, err := rules.Parse([]byte(`{"rules": [` + ruleJSON + `]}`))
	if err != nil {
		t.Fatalf("parse rules: %v", err)
	}
	return rules.NewLoader(set)
}

const bruteForceRule = `{
	"id": "R-BRUTE", "version": 1, "name": "brute force",
	"severity": "high", "event_type": "login_failed",
	"window_seconds": 60, "threshold": 3, "suppress_seconds": 30
}`

func ev(id, entity string, at time.Time) Event {
	return Event{ID: id, Type: "login_failed", Timestamp: at, Entity: entity}
}

func TestOutOfOrderReplayDeterministic(t *testing.T) {
	t.Log("业务: 乱序事件 —— 同一事件流任意乱序重放, 告警结果必须完全一致")
	// 12 个事件, 乱序后应触发: t=20s 首次达标, 后续持续在窗口内达标,
	// 30s 抑制窗口内合并为一条带次数的告警。
	var events []Event
	for i := 0; i < 12; i++ {
		events = append(events, ev(fmt.Sprintf("e%02d", i), "alice", base.Add(time.Duration(i*10)*time.Second)))
	}

	run := func(order []Event) []Alert {
		eng := New(testLoader(t, bruteForceRule), 10*time.Minute)
		for _, e := range order {
			eng.Ingest(e)
		}
		return eng.Alerts()
	}

	want := run(events)
	for trial := 0; trial < 20; trial++ {
		shuffled := append([]Event(nil), events...)
		rand.New(rand.NewSource(int64(trial))).Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		got := run(shuffled)
		if fmt.Sprintf("%v", got) != fmt.Sprintf("%v", want) {
			t.Fatalf("trial %d: shuffled replay produced different alerts:\n got: %+v\nwant: %+v", trial, got, want)
		}
	}
	a := want[0]
	t.Logf("用例通过: 20 次乱序重放告警一致 (alert=%s rule=%s v%d count=%d events=%v)",
		a.ID, a.RuleID, a.RuleVersion, a.Count, a.EventIDs)
}

func TestLateEventWithinToleranceAffectsConclusion(t *testing.T) {
	t.Log("业务: 乱序事件 —— 可容忍范围内的迟到事件必须正确改变检测结论")
	eng := New(testLoader(t, bruteForceRule), 30*time.Second)
	eng.Ingest(ev("e1", "alice", base))
	eng.Ingest(ev("e3", "alice", base.Add(40*time.Second)))
	eng.Ingest(ev("e9", "alice", base.Add(90*time.Second))) // 推进水位线
	if len(eng.Alerts()) != 0 {
		t.Fatal("only 2 events in window, no alert expected yet")
	}
	// e2 迟到 50s, 在 30s 容忍度内? 不在 —— 改用 20s 前的迟到事件。
	res := eng.Ingest(ev("e2", "alice", base.Add(70*time.Second)))
	if !res.Accepted {
		t.Fatalf("late event within tolerance must be accepted: %s", res.Reason)
	}
	alerts := eng.Alerts()
	if len(alerts) != 1 {
		t.Fatalf("late event should complete the window and fire 1 alert, got %d", len(alerts))
	}
	for _, id := range []string{"e2", "e3", "e9"} {
		if !strings.Contains(fmt.Sprint(alerts[0].EventIDs), id) {
			t.Fatalf("alert must trace event %s, got %v", id, alerts[0].EventIDs)
		}
	}
	t.Logf("用例通过: 迟到事件 e2 触发告警 %s, 溯源事件=%v", alerts[0].ID, alerts[0].EventIDs)
}

func TestLateEventBeyondToleranceMarkedNotDropped(t *testing.T) {
	t.Log("业务: 乱序事件 —— 超出容忍度的迟到事件必须被明确标记, 不得悄悄丢弃")
	eng := New(testLoader(t, bruteForceRule), 10*time.Second)
	eng.Ingest(ev("e1", "alice", base))
	eng.Ingest(ev("e2", "alice", base.Add(100*time.Second))) // 水位线推进到 +100s
	res := eng.Ingest(ev("e0", "alice", base.Add(50*time.Second)))
	if !res.Late || res.Accepted {
		t.Fatalf("event beyond tolerance must be rejected as late, got %+v", res)
	}
	late := eng.LateEvents()
	if len(late) != 1 || late[0].Event.ID != "e0" {
		t.Fatalf("late event must be recorded, got %+v", late)
	}
	t.Logf("用例通过: 迟到事件被标记并记录原因: %s", late[0].Reason)
}

func TestSuppressionMergesRepeatedTriggers(t *testing.T) {
	t.Log("业务: 告警抑制与合并 —— 同规则同实体短时间重复触发合并为一条带次数告警")
	eng := New(testLoader(t, bruteForceRule), 2*time.Minute)
	// 窗口 60s 内 6 个事件 -> 多次触发, 但都在 30s 抑制窗口内 -> 1 条告警。
	for i := 0; i < 6; i++ {
		eng.Ingest(ev(fmt.Sprintf("a%d", i), "alice", base.Add(time.Duration(i*10)*time.Second)))
	}
	// 另一实体同样触发 -> 独立告警, 不得被吞并。
	for i := 0; i < 3; i++ {
		eng.Ingest(ev(fmt.Sprintf("b%d", i), "bob", base.Add(time.Duration(i*10)*time.Second)))
	}
	alerts := eng.Alerts()
	if len(alerts) != 2 {
		t.Fatalf("expected 2 alerts (alice merged + bob), got %d: %+v", len(alerts), alerts)
	}
	var alice, bob *Alert
	for i := range alerts {
		switch alerts[i].Entity {
		case "alice":
			alice = &alerts[i]
		case "bob":
			bob = &alerts[i]
		}
	}
	if alice == nil || bob == nil {
		t.Fatalf("alerts for both entities expected, got %+v", alerts)
	}
	if alice.Count < 2 {
		t.Fatalf("alice's repeated triggers should merge into one alert with count>1, got %d", alice.Count)
	}
	if bob.Count != 1 {
		t.Fatalf("bob fired once, count must be 1, got %d", bob.Count)
	}
	if alice.RuleID != "R-BRUTE" || alice.RuleVersion != 1 {
		t.Fatalf("alert must carry rule id and version, got %+v", alice)
	}
	t.Logf("用例通过: alice 合并告警 count=%d, bob 独立告警 count=%d, 互不吞并", alice.Count, bob.Count)
}

func TestSuppressionDoesNotMergeAcrossRules(t *testing.T) {
	t.Log("业务: 告警抑制与合并 —— 不同规则之间不得互相吞并")
	two := bruteForceRule + `,{
		"id": "R-BRUTE-2", "version": 1, "name": "brute force strict",
		"severity": "critical", "event_type": "login_failed",
		"window_seconds": 60, "threshold": 3, "suppress_seconds": 30
	}`
	eng := New(testLoader(t, two), 2*time.Minute)
	for i := 0; i < 3; i++ {
		eng.Ingest(ev(fmt.Sprintf("e%d", i), "alice", base.Add(time.Duration(i*10)*time.Second)))
	}
	alerts := eng.Alerts()
	if len(alerts) != 2 {
		t.Fatalf("same entity, two rules -> 2 independent alerts, got %d", len(alerts))
	}
	if alerts[0].RuleID == alerts[1].RuleID {
		t.Fatalf("alerts must belong to different rules: %+v", alerts)
	}
	t.Logf("用例通过: 规则 %s 与 %s 各自产生独立告警", alerts[0].RuleID, alerts[1].RuleID)
}

func TestConcurrentIngestNoDupNoLoss(t *testing.T) {
	t.Log("业务: 并发写入 —— 并发摄入不得重复或漏报, 重复 event_id 必须去重")
	eng := New(testLoader(t, bruteForceRule), time.Hour)
	const goroutines, perG = 8, 50
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				eng.Ingest(ev(fmt.Sprintf("g%02d-e%03d", g, i), "alice",
					base.Add(time.Duration(g*perG+i)*time.Second)))
			}
		}(g)
	}
	wg.Wait()
	// 每个事件都重复投递一次, 必须全部被去重。
	var wg2 sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg2.Add(1)
		go func(g int) {
			defer wg2.Done()
			for i := 0; i < perG; i++ {
				res := eng.Ingest(ev(fmt.Sprintf("g%02d-e%03d", g, i), "alice",
					base.Add(time.Duration(g*perG+i)*time.Second)))
				if res.Accepted {
					t.Errorf("duplicate event_id must not be accepted twice")
				}
			}
		}(g)
	}
	wg2.Wait()

	// 与单线程顺序摄入的结果对比, 必须完全一致。
	seq := New(testLoader(t, bruteForceRule), time.Hour)
	for g := 0; g < goroutines; g++ {
		for i := 0; i < perG; i++ {
			seq.Ingest(ev(fmt.Sprintf("g%02d-e%03d", g, i), "alice",
				base.Add(time.Duration(g*perG+i)*time.Second)))
		}
	}
	got, want := eng.Alerts(), seq.Alerts()
	if fmt.Sprintf("%v", got) != fmt.Sprintf("%v", want) {
		t.Fatalf("concurrent ingest diverged from sequential:\n got: %+v\nwant: %+v", got, want)
	}
	total := 0
	for _, a := range got {
		total += a.Count
	}
	t.Logf("用例通过: %d 事件并发摄入 + 全量重复投递, 告警与顺序执行一致 (%d 条告警, 累计触发 %d 次)",
		goroutines*perG, len(got), total)
}

func TestWindowStateGarbageCollected(t *testing.T) {
	t.Log("业务: 窗口状态清理 —— 过期状态及时回收, 长时间运行内存不无界增长")
	eng := New(testLoader(t, bruteForceRule), 30*time.Second)
	// 模拟长时间运行: 10000 个事件跨越很长的时间范围。
	for i := 0; i < 10000; i++ {
		eng.Ingest(ev(fmt.Sprintf("e%05d", i), fmt.Sprintf("user-%d", i%50),
			base.Add(time.Duration(i)*time.Minute)))
	}
	buckets, buffered, open := eng.Stats()
	if buffered > 50*3 { // 窗口 60s, 事件间隔 60s, 每实体至多缓冲极少量事件
		t.Fatalf("buffered events must stay bounded, got %d", buffered)
	}
	t.Logf("用例通过: 10000 事件后状态有界 (buckets=%d bufferedEvents=%d openAlerts=%d)",
		buckets, buffered, open)
}

func TestHotReloadKeepsEngineConsistent(t *testing.T) {
	t.Log("业务: 规则热更新 —— 引擎运行中更新规则, 失败保留旧规则, 删除的规则状态被清理")
	loader := testLoader(t, bruteForceRule)
	eng := New(loader, 30*time.Second)
	for i := 0; i < 2; i++ {
		eng.Ingest(ev(fmt.Sprintf("e%d", i), "alice", base.Add(time.Duration(i*10)*time.Second)))
	}
	// 热更新失败: 旧规则继续工作。
	if _, err := loader.ReloadReader(strings.NewReader(`{"rules": [{"id": "R-BRUTE"}]}`)); err == nil {
		t.Fatal("invalid rule set must be rejected")
	}
	eng.Ingest(ev("e2", "alice", base.Add(20*time.Second)))
	if len(eng.Alerts()) != 1 {
		t.Fatalf("old rule must keep working after failed reload, got %d alerts", len(eng.Alerts()))
	}
	t.Log("用例通过: 失败的热更新不影响在役规则, 第 3 个事件正常触发告警")

	// 热更新成功: 阈值提高到 5, 旧阈值不再触发。
	v2 := strings.Replace(bruteForceRule, `"threshold": 3`, `"threshold": 5`, 1)
	v2 = strings.Replace(v2, `"version": 1`, `"version": 2`, 1)
	if _, err := loader.ReloadReader(strings.NewReader(`{"rules": [` + v2 + `]}`)); err != nil {
		t.Fatal(err)
	}
	eng.Ingest(ev("e3", "alice", base.Add(30*time.Second))) // 窗口内 4 个, 不足新阈值 5
	if got := eng.Alerts(); len(got) != 1 {
		t.Fatalf("new threshold 5 must apply atomically, got %d alerts", len(got))
	}
	eng.Ingest(ev("e4", "alice", base.Add(40*time.Second))) // 窗口内 5 个, 触发
	alerts := eng.Alerts()
	if len(alerts) != 1 || alerts[0].Count != 2 || alerts[0].RuleVersion != 2 {
		t.Fatalf("expected merged alert with count=2 and rule version 2, got %+v", alerts)
	}
	t.Logf("用例通过: 新规则(version 2, 阈值 5)原子生效, 告警 %s 合并后 count=%d version=%d",
		alerts[0].ID, alerts[0].Count, alerts[0].RuleVersion)
}
