package blockpolicy

import (
	"regexp"

	blockytrie "github.com/0xERR0R/blocky/trie"
)

type decisionAction string

const (
	actionAllow decisionAction = "allow"
	actionBlock decisionAction = "block"
)

type QueryType int

const (
	queryTypeOther QueryType = iota
	queryTypeA
	queryTypeAAAA
)

type Decision struct {
	Action decisionAction
	Code   decisionCode
	IP     string
	Reason string
	Mode   blockMode
}

type decisionCode int

const (
	codePass decisionCode = iota
	codeNXDomain
	codeSyntheticIP
)

type Engine struct {
	mode  blockMode
	allow matcherSet
	deny  matcherSet
}

func NewEngine(mode blockMode, allow, deny map[string]struct{}) *Engine {
	if allow == nil {
		allow = map[string]struct{}{}
	}
	if deny == nil {
		deny = map[string]struct{}{}
	}
	return NewEngineWithMatchers(mode, matcherSet{exact: allow}, matcherSet{exact: deny})
}

func NewEngineWithMatchers(mode blockMode, allow, deny matcherSet) *Engine {
	return &Engine{
		mode:  mode,
		allow: allow,
		deny:  deny,
	}
}

func (e *Engine) Evaluate(name string, qtype QueryType) Decision {
	n := normalizeQueryName(name)
	if e.allow.matches(n) {
		return Decision{Action: actionAllow, Code: codePass, Reason: "allowlist"}
	}
	if !e.deny.matches(n) {
		return Decision{Action: actionAllow, Code: codePass, Reason: "passthrough"}
	}

	if e.mode == modeNXDomain {
		return Decision{Action: actionBlock, Code: codeNXDomain, Reason: "denylist", Mode: modeNXDomain}
	}

	switch qtype {
	case queryTypeA:
		return Decision{Action: actionBlock, Code: codeSyntheticIP, IP: "0.0.0.0", Reason: "denylist", Mode: modeZeroIP}
	case queryTypeAAAA:
		return Decision{Action: actionBlock, Code: codeSyntheticIP, IP: "::", Reason: "denylist", Mode: modeZeroIP}
	default:
		return Decision{Action: actionBlock, Code: codeNXDomain, Reason: "denylist", Mode: modeZeroIP}
	}
}

type matcherSet struct {
	exact    map[string]struct{}
	wildcard *blockytrie.Trie
	regex    []*regexp.Regexp
}

func (s matcherSet) matches(name string) bool {
	if len(s.exact) > 0 {
		if _, ok := s.exact[name]; ok {
			return true
		}
	}
	if s.wildcard != nil && !s.wildcard.IsEmpty() && s.wildcard.HasParentOf(name) {
		return true
	}
	for _, re := range s.regex {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}
