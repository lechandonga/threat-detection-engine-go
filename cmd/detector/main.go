// detector 是本地验证入口: 加载规则文件, 逐行消费 JSONL 事件流,
// 可选地在中途执行一次规则热更新, 最后输出全部告警与被拒绝的迟到事件。
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/lechandonga/threat-detection-engine-go/internal/engine"
	"github.com/lechandonga/threat-detection-engine-go/internal/rules"
)

func main() {
	rulesPath := flag.String("rules", "examples/rules.json", "path to the rule file")
	eventsPath := flag.String("events", "examples/events.jsonl", "path to the JSONL event stream")
	reloadPath := flag.String("reload", "", "optional: hot-reload rules from this file after -reload-at events")
	reloadAt := flag.Int("reload-at", 0, "number of events to ingest before hot reload")
	lateness := flag.Duration("lateness", 30*time.Second, "allowed event-time lateness for out-of-order events")
	flag.Parse()

	set, err := rules.LoadFile(*rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load rules: %v\n", err)
		os.Exit(1)
	}
	loader := rules.NewLoader(set)
	fmt.Printf("loaded %d rule(s) from %s\n", set.Len(), *rulesPath)

	eng := engine.New(loader, *lateness)

	f, err := os.Open(*eventsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open events: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	var accepted, rejected, late int
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		if *reloadPath != "" && *reloadAt > 0 && accepted+rejected+late == *reloadAt {
			if _, err := loader.Reload(*reloadPath); err != nil {
				fmt.Printf("hot reload REJECTED (old rules stay active): %v\n", err)
			} else {
				fmt.Printf("hot reload OK: %d rule(s) now active\n", loader.Current().Len())
			}
		}
		var ev engine.Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			fmt.Fprintf(os.Stderr, "line %d: bad event JSON: %v\n", line, err)
			rejected++
			continue
		}
		res := eng.Ingest(ev)
		switch {
		case res.Accepted:
			accepted++
		case res.Late:
			late++
			fmt.Printf("LATE  %s: %s\n", ev.ID, res.Reason)
		default:
			rejected++
			fmt.Printf("SKIP  %s: %s\n", ev.ID, res.Reason)
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "read events: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\ningested: %d accepted, %d late, %d rejected\n", accepted, late, rejected)
	alerts := eng.Alerts()
	fmt.Printf("alerts: %d\n", len(alerts))
	out, _ := json.MarshalIndent(alerts, "", "  ")
	fmt.Println(string(out))
}
