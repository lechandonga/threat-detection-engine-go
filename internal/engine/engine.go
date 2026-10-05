// Package engine implements a local streaming threat-detection and alert
// correlation engine. It correlates events in event-time sliding windows,
// tolerates bounded out-of-order arrivals, and merges repeated alerts.
package engine

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/lechandonga/threat-detection-engine-go/internal/rules"
)

// Event is one normalized security-log event from the local event stream.
type Event struct {
	ID        string            `json:"event_id"`
	Type      string            `json:"event_type"`
	Timestamp time.Time         `json:"timestamp"` // event time; window assignment is based on it
	Entity    string            `json:"entity"`    // correlation entity (user, host, ip, ...)
	Fields    map[string]string `json:"fields,omitempty"`
}

// Alert is a (possibly merged) detection result. It is fully explainable:
// it carries the triggering events, the matched rule and the rule version.
type Alert struct {
	ID          string    `json:"id"`
	RuleID      string    `json:"rule_id"`
	RuleName    string    `json:"rule_name"`
	RuleVersion int       `json:"rule_version"`
	Severity    string    `json:"severity"`
	Entity      string    `json:"entity"`
	Count       int       `json:"count"` // number of merged triggers
	FirstAt     time.Time `json:"first_at"`
	LastAt      time.Time `json:"last_at"`
	EventIDs    []string  `json:"event_ids"` // events that caused every merged trigger
}

// LateEvent records an event that arrived beyond the allowed lateness and
// was explicitly rejected instead of being silently dropped.
type LateEvent struct {
	Event     Event     `json:"event"`
	Watermark time.Time `json:"watermark"`
	Reason    string    `json:"reason"`
}

// IngestResult reports what happened to one ingested event.
type IngestResult struct {
	Accepted bool
	Late     bool
	Reason   string
}

type bucketKey struct {
	ruleID string
	entity string
}

// bucket holds the matched events of one (rule, entity) pair, sorted by
// event time. Triggers are recomputed deterministically from this list, so
// out-of-order arrival never changes the final conclusion.
type bucket struct {
	events []Event // sorted by (Timestamp, ID)
	fired  map[time.Time]bool
}

// trigger is one window firing derived from a bucket's event list.
type trigger struct {
	at       time.Time
	eventIDs []string
}

// Engine is the streaming correlation engine. It is safe for concurrent use.
type Engine struct {
	mu              sync.Mutex
	loader          *rules.Loader
	allowedLateness time.Duration

	watermark time.Time
	seenIDs   map[string]struct{} // idempotency: exact duplicate deliveries are dropped
	buckets   map[bucketKey]*bucket

	open   map[bucketKey][]*openAlert // alerts still inside their suppression window
	alerts []*Alert                   // every alert, open or closed
	late   []LateEvent
}

// openAlert tracks an alert that can still absorb new triggers, together
// with the sorted event-times of every trigger merged into it so far.
// Merging is defined on trigger-time proximity (a connected component of
// triggers whose pairwise gaps are within the suppression window), which
// makes the final result independent of arrival order.
type openAlert struct {
	alert *Alert
	times []time.Time
}

// New creates an Engine. allowedLateness is the maximum event-time delay an
// out-of-order event may have relative to the current watermark and still
// affect detection conclusions.
func New(loader *rules.Loader, allowedLateness time.Duration) *Engine {
	return &Engine{
		loader:          loader,
		allowedLateness: allowedLateness,
		seenIDs:         make(map[string]struct{}),
		buckets:         make(map[bucketKey]*bucket),
		open:            make(map[bucketKey][]*openAlert),
	}
}

// Ingest feeds one event into the engine. The result tells the caller
// whether the event was accepted, deduplicated, or rejected as too late.
func (e *Engine) Ingest(ev Event) IngestResult {
	e.mu.Lock()
	defer e.mu.Unlock()

	if ev.ID == "" || ev.Type == "" || ev.Entity == "" || ev.Timestamp.IsZero() {
		return IngestResult{Reason: "event missing required field (event_id/event_type/entity/timestamp)"}
	}
	if _, dup := e.seenIDs[ev.ID]; dup {
		return IngestResult{Reason: "duplicate event_id, ignored"}
	}
	if !e.watermark.IsZero() && ev.Timestamp.Before(e.watermark.Add(-e.allowedLateness)) {
		e.late = append(e.late, LateEvent{
			Event:     ev,
			Watermark: e.watermark,
			Reason: fmt.Sprintf("event time %s is beyond allowed lateness %s behind watermark %s",
				ev.Timestamp.Format(time.RFC3339), e.allowedLateness, e.watermark.Format(time.RFC3339)),
		})
		return IngestResult{Late: true, Reason: "event arrived too late and was rejected"}
	}

	e.seenIDs[ev.ID] = struct{}{}
	if ev.Timestamp.After(e.watermark) {
		e.watermark = ev.Timestamp
	}

	set := e.loader.Current()
	for _, rule := range set.All() {
		if !matches(rule, ev) {
			continue
		}
		key := bucketKey{ruleID: rule.ID, entity: ev.Entity}
		b := e.buckets[key]
		if b == nil {
			b = &bucket{fired: make(map[time.Time]bool)}
			e.buckets[key] = b
		}
		b.insert(ev)
		e.evaluate(key, b, rule)
	}
	e.gcLocked()
	return IngestResult{Accepted: true}
}

// matches reports whether an event matches a rule's type and field filters.
func matches(rule *rules.Rule, ev Event) bool {
	if ev.Type != rule.EventType {
		return false
	}
	for k, want := range rule.FieldEquals {
		if ev.Fields[k] != want {
			return false
		}
	}
	return true
}

// insert adds an event keeping the bucket sorted by (Timestamp, ID).
func (b *bucket) insert(ev Event) {
	i := sort.Search(len(b.events), func(i int) bool {
		cur := b.events[i]
		if cur.Timestamp.Equal(ev.Timestamp) {
			return cur.ID >= ev.ID
		}
		return cur.Timestamp.After(ev.Timestamp)
	})
	b.events = append(b.events, Event{})
	copy(b.events[i+1:], b.events[i:])
	b.events[i] = ev
}

// computeTriggers derives every window firing from the sorted event list.
// A firing happens at event time t when t is the earliest event time at
// which the window (t-W, t] contains at least threshold events. This is a
// pure function of the event set, so replaying the same events in any order
// yields the same triggers.
func computeTriggers(events []Event, window time.Duration, threshold int) []trigger {
	var out []trigger
	start := 0
	for end := range events {
		limit := events[end].Timestamp.Add(-window)
		for start < end && !events[start].Timestamp.After(limit) {
			start++
		}
		if end-start+1 >= threshold {
			// The window first reaches the threshold at the newest event's
			// own event time.
			t := events[end].Timestamp
			if len(out) == 0 || t.After(out[len(out)-1].at) {
				ids := make([]string, 0, end-start+1)
				for _, ev := range events[start : end+1] {
					ids = append(ids, ev.ID)
				}
				out = append(out, trigger{at: t, eventIDs: ids})
			}
		}
	}
	return out
}

// evaluate recomputes the bucket's triggers and emits alerts for triggers
// that have not fired yet, applying suppression/merge per (rule, entity).
func (e *Engine) evaluate(key bucketKey, b *bucket, rule *rules.Rule) {
	window := time.Duration(rule.WindowSeconds) * time.Second
	triggers := computeTriggers(b.events, window, rule.Threshold)
	suppress := time.Duration(rule.SuppressSeconds) * time.Second
	for _, trg := range triggers {
		if b.fired[trg.at] {
			continue
		}
		b.fired[trg.at] = true
		e.absorbTrigger(key, rule, trg, suppress)
	}
}

// absorbTrigger merges one new trigger into every open alert of this
// (rule, entity) whose trigger times are within the suppression window of
// the new trigger, or creates a new alert when none qualifies. When several
// open alerts become connected through the new trigger they are merged into
// one, keeping the final outcome independent of arrival order.
func (e *Engine) absorbTrigger(key bucketKey, rule *rules.Rule, trg trigger, suppress time.Duration) {
	open := e.open[key]
	var matched []*openAlert
	var rest []*openAlert
	for _, oa := range open {
		if withinAny(oa.times, trg.at, suppress) {
			matched = append(matched, oa)
		} else {
			rest = append(rest, oa)
		}
	}
	if len(matched) == 0 {
		alert := &Alert{
			ID:          alertID(rule.ID, key.entity, trg.at),
			RuleID:      rule.ID,
			RuleName:    rule.Name,
			RuleVersion: rule.Version,
			Severity:    rule.Severity,
			Entity:      key.entity,
			Count:       1,
			FirstAt:     trg.at,
			LastAt:      trg.at,
			EventIDs:    append([]string(nil), trg.eventIDs...),
		}
		e.open[key] = append(open, &openAlert{alert: alert, times: []time.Time{trg.at}})
		e.alerts = append(e.alerts, alert)
		return
	}
	target := matched[0]
	for _, other := range matched[1:] {
		target.times = mergeTimes(target.times, other.times)
		target.alert.EventIDs = mergeIDs(target.alert.EventIDs, other.alert.EventIDs)
		// The absorbed alert is removed from the output list.
		for i, a := range e.alerts {
			if a == other.alert {
				e.alerts = append(e.alerts[:i], e.alerts[i+1:]...)
				break
			}
		}
	}
	target.times = insertTime(target.times, trg.at)
	target.alert.Count = len(target.times)
	target.alert.FirstAt = target.times[0]
	target.alert.LastAt = target.times[len(target.times)-1]
	target.alert.ID = alertID(rule.ID, key.entity, target.alert.FirstAt)
	target.alert.EventIDs = mergeIDs(target.alert.EventIDs, trg.eventIDs)
	// A hot-reloaded rule may have a new version; the alert records the
	// version of the rule that most recently triggered it.
	target.alert.RuleVersion = rule.Version
	e.open[key] = append(rest, target)
}

// alertID derives a deterministic alert ID from its identity and first
// trigger time, so replays and concurrent interleavings converge.
func alertID(ruleID, entity string, firstAt time.Time) string {
	return fmt.Sprintf("ALERT-%s-%s-%s", ruleID, entity, firstAt.UTC().Format("20060102T150405Z"))
}

// withinAny reports whether any time in ts is within d of t (either side).
func withinAny(ts []time.Time, t time.Time, d time.Duration) bool {
	i := sort.Search(len(ts), func(i int) bool { return !ts[i].Before(t) })
	if i < len(ts) && !ts[i].After(t.Add(d)) {
		return true
	}
	if i > 0 && !ts[i-1].Before(t.Add(-d)) {
		return true
	}
	return false
}

// insertTime inserts t into the sorted slice ts.
func insertTime(ts []time.Time, t time.Time) []time.Time {
	i := sort.Search(len(ts), func(i int) bool { return !ts[i].Before(t) })
	ts = append(ts, time.Time{})
	copy(ts[i+1:], ts[i:])
	ts[i] = t
	return ts
}

// mergeTimes unions two sorted time slices.
func mergeTimes(a, b []time.Time) []time.Time {
	out := append([]time.Time(nil), a...)
	for _, t := range b {
		out = insertTime(out, t)
	}
	return out
}

// mergeIDs unions two sorted event-ID lists, keeping deterministic order.
func mergeIDs(a, b []string) []string {
	set := make(map[string]struct{}, len(a)+len(b))
	for _, id := range a {
		set[id] = struct{}{}
	}
	for _, id := range b {
		set[id] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// gcLocked prunes expired window state so long-running memory stays bounded.
// Events older than watermark - window - allowedLateness can never influence
// any future trigger and are removed; empty buckets and fully expired
// suppression entries are deleted.
func (e *Engine) gcLocked() {
	if e.watermark.IsZero() {
		return
	}
	set := e.loader.Current()
	for key, b := range e.buckets {
		rule, ok := set.ByID(key.ruleID)
		if !ok {
			// Rule removed by hot reload: drop its state entirely.
			delete(e.buckets, key)
			delete(e.open, key)
			continue
		}
		horizon := e.watermark.Add(-time.Duration(rule.WindowSeconds)*time.Second - e.allowedLateness)
		keep := sort.Search(len(b.events), func(i int) bool {
			return b.events[i].Timestamp.After(horizon)
		})
		if keep > 0 {
			b.events = append([]Event(nil), b.events[keep:]...)
		}
		// Triggers at or before the horizon can never be referenced again.
		for t := range b.fired {
			if !t.After(horizon) {
				delete(b.fired, t)
			}
		}
		if len(b.events) == 0 && len(b.fired) == 0 {
			delete(e.buckets, key)
		}
		if open := e.open[key]; len(open) > 0 {
			expireBefore := e.watermark.Add(-time.Duration(rule.SuppressSeconds)*time.Second - e.allowedLateness)
			kept := open[:0]
			for _, oa := range open {
				if oa.alert.LastAt.After(expireBefore) {
					kept = append(kept, oa)
				}
			}
			if len(kept) == 0 {
				delete(e.open, key)
			} else {
				e.open[key] = kept
			}
		}
	}
}

// Alerts returns a snapshot of all alerts (open and closed) in emission
// order. The returned slice is a copy; alert contents are not mutated after
// the caller observes them via this snapshot.
func (e *Engine) Alerts() []Alert {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Alert, len(e.alerts))
	for i, a := range e.alerts {
		out[i] = *a
		out[i].EventIDs = append([]string(nil), a.EventIDs...)
	}
	return out
}

// LateEvents returns every event rejected for exceeding the allowed
// lateness, in rejection order.
func (e *Engine) LateEvents() []LateEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]LateEvent(nil), e.late...)
}

// Stats exposes internal state sizes for observability and tests.
func (e *Engine) Stats() (buckets, bufferedEvents, openAlerts int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, b := range e.buckets {
		bufferedEvents += len(b.events)
	}
	for _, open := range e.open {
		openAlerts += len(open)
	}
	return len(e.buckets), bufferedEvents, openAlerts
}
