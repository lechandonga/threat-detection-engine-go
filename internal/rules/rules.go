// Package rules provides strict local loading, validation and atomic
// hot-reload of detection rules.
package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync/atomic"
)

// ReasonCode classifies why a rule (or rule file) was rejected, so callers
// can distinguish failure causes programmatically.
type ReasonCode string

const (
	ReasonInvalidJSON  ReasonCode = "INVALID_JSON"  // file is not valid JSON
	ReasonUnknownField ReasonCode = "UNKNOWN_FIELD" // a field is not defined in the schema
	ReasonDuplicateID  ReasonCode = "DUPLICATE_ID"  // rule id defined more than once
	ReasonInvalidField ReasonCode = "INVALID_FIELD" // field value failed validation
)

// Rejection describes one rejected rule (or a file-level problem).
type Rejection struct {
	Code   ReasonCode `json:"code"`
	RuleID string     `json:"rule_id,omitempty"`
	Field  string     `json:"field,omitempty"`
	Detail string     `json:"detail"`
}

func (r Rejection) Error() string {
	if r.RuleID != "" {
		return fmt.Sprintf("rule %q: %s: %s (field: %s)", r.RuleID, r.Code, r.Detail, r.Field)
	}
	return fmt.Sprintf("%s: %s (field: %s)", r.Code, r.Detail, r.Field)
}

// LoadError aggregates every rejection found during one load attempt.
type LoadError struct {
	Rejections []Rejection
}

func (e *LoadError) Error() string {
	return fmt.Sprintf("rule load rejected: %d problem(s), first: %v", len(e.Rejections), e.Rejections[0])
}

// HasCode reports whether the rejections include the given reason code.
func (e *LoadError) HasCode(code ReasonCode) bool {
	for _, r := range e.Rejections {
		if r.Code == code {
			return true
		}
	}
	return false
}

// Rule is a single sliding-window correlation rule.
type Rule struct {
	ID              string            `json:"id"`
	Version         int               `json:"version"`
	Name            string            `json:"name"`
	Description     string            `json:"description,omitempty"`
	Severity        string            `json:"severity"`               // low|medium|high|critical
	EventType       string            `json:"event_type"`             // only events of this type are correlated
	FieldEquals     map[string]string `json:"field_equals,omitempty"` // event fields must all equal these values
	WindowSeconds   int               `json:"window_seconds"`         // sliding window length in event time
	Threshold       int               `json:"threshold"`              // matching events inside the window needed to fire
	SuppressSeconds int               `json:"suppress_seconds"`       // merge window for repeated alerts on same rule+entity
}

func (r *Rule) validate() []Rejection {
	var out []Rejection
	bad := func(field, format string, args ...any) {
		out = append(out, Rejection{
			Code:   ReasonInvalidField,
			RuleID: r.ID,
			Field:  field,
			Detail: fmt.Sprintf(format, args...),
		})
	}
	if r.ID == "" {
		bad("id", "must not be empty")
	}
	if r.Version <= 0 {
		bad("version", "must be a positive integer, got %d", r.Version)
	}
	if r.Name == "" {
		bad("name", "must not be empty")
	}
	switch r.Severity {
	case "low", "medium", "high", "critical":
	default:
		bad("severity", "must be one of low/medium/high/critical, got %q", r.Severity)
	}
	if r.EventType == "" {
		bad("event_type", "must not be empty")
	}
	if r.WindowSeconds <= 0 {
		bad("window_seconds", "must be positive, got %d", r.WindowSeconds)
	}
	if r.Threshold <= 0 {
		bad("threshold", "must be positive, got %d", r.Threshold)
	}
	if r.SuppressSeconds < 0 {
		bad("suppress_seconds", "must be >= 0, got %d", r.SuppressSeconds)
	}
	return out
}

// fileFormat is the top-level structure of a rule file.
type fileFormat struct {
	Rules []json.RawMessage `json:"rules"`
}

// ruleFieldNames is the set of fields allowed in a rule, used to report
// precise unknown-field errors.
var ruleFieldNames = map[string]bool{
	"id": true, "version": true, "name": true, "description": true,
	"severity": true, "event_type": true, "field_equals": true,
	"window_seconds": true, "threshold": true, "suppress_seconds": true,
}

// RuleSet is an immutable, validated collection of rules indexed by ID.
type RuleSet struct {
	byID map[string]*Rule
	all  []*Rule // sorted by ID for deterministic iteration
}

// ByID looks up a rule by ID.
func (s *RuleSet) ByID(id string) (*Rule, bool) {
	r, ok := s.byID[id]
	return r, ok
}

// All returns every rule sorted by ID.
func (s *RuleSet) All() []*Rule { return append([]*Rule(nil), s.all...) }

// Len returns the number of rules.
func (s *RuleSet) Len() int { return len(s.all) }

// Parse strictly parses and validates a rule set. Any invalid rule fails the
// whole file; nothing is silently skipped, and every problem is reported as
// a Rejection with a distinguishable ReasonCode.
func Parse(data []byte) (*RuleSet, error) {
	var file fileFormat
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, &LoadError{Rejections: []Rejection{{
			Code:   classifyDecodeError(err),
			Field:  "rules",
			Detail: err.Error(),
		}}}
	}
	if len(file.Rules) == 0 {
		return nil, &LoadError{Rejections: []Rejection{{
			Code:   ReasonInvalidField,
			Field:  "rules",
			Detail: "rule file must contain at least one rule",
		}}}
	}

	var rejections []Rejection
	set := &RuleSet{byID: make(map[string]*Rule, len(file.Rules))}
	for i, raw := range file.Rules {
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(raw, &probe); err != nil {
			rejections = append(rejections, Rejection{
				Code:   ReasonInvalidJSON,
				Detail: fmt.Sprintf("rules[%d]: %v", i, err),
			})
			continue
		}
		unknown := false
		for name := range probe {
			if !ruleFieldNames[name] {
				rejections = append(rejections, Rejection{
					Code:   ReasonUnknownField,
					Field:  name,
					Detail: fmt.Sprintf("rules[%d] contains unknown field %q", i, name),
				})
				unknown = true
			}
		}
		if unknown {
			continue
		}
		var rule Rule
		if err := json.Unmarshal(raw, &rule); err != nil {
			rejections = append(rejections, Rejection{
				Code:   ReasonInvalidJSON,
				Detail: fmt.Sprintf("rules[%d]: %v", i, err),
			})
			continue
		}
		if rej := rule.validate(); len(rej) > 0 {
			rejections = append(rejections, rej...)
			continue
		}
		if _, dup := set.byID[rule.ID]; dup {
			rejections = append(rejections, Rejection{
				Code:   ReasonDuplicateID,
				RuleID: rule.ID,
				Field:  "id",
				Detail: fmt.Sprintf("rule id %q is defined more than once", rule.ID),
			})
			continue
		}
		r := rule
		set.byID[r.ID] = &r
		set.all = append(set.all, &r)
	}
	if len(rejections) > 0 {
		return nil, &LoadError{Rejections: rejections}
	}
	sort.Slice(set.all, func(i, j int) bool { return set.all[i].ID < set.all[j].ID })
	return set, nil
}

func classifyDecodeError(err error) ReasonCode {
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return ReasonInvalidJSON
	}
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &syntaxErr) || errors.As(err, &typeErr) {
		return ReasonInvalidJSON
	}
	return ReasonUnknownField
}

// LoadFile loads and validates a rule set from a local file.
func LoadFile(path string) (*RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rule file: %w", err)
	}
	return Parse(data)
}

// Loader holds the currently active rule set and supports atomic hot reload:
// an update either takes effect as a whole or fails while the previous rule
// set keeps serving. Old and new rules are never mixed.
type Loader struct {
	current atomic.Value // stores *RuleSet
}

// NewLoader creates a Loader with an initial rule set.
func NewLoader(initial *RuleSet) *Loader {
	l := &Loader{}
	l.current.Store(initial)
	return l
}

// Current returns the currently active rule set (concurrency safe).
func (l *Loader) Current() *RuleSet { return l.current.Load().(*RuleSet) }

// Reload loads new rules from a file and atomically swaps them in. On any
// error the previous rule set stays active.
func (l *Loader) Reload(path string) (*RuleSet, error) {
	set, err := LoadFile(path)
	if err != nil {
		return nil, err
	}
	l.current.Store(set)
	return set, nil
}

// ReloadReader is like Reload but reads from an io.Reader.
func (l *Loader) ReloadReader(r io.Reader) (*RuleSet, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	set, err := Parse(data)
	if err != nil {
		return nil, err
	}
	l.current.Store(set)
	return set, nil
}
