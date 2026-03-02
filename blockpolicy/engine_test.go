package blockpolicy

import (
	"regexp"
	"testing"

	blockytrie "github.com/0xERR0R/blocky/trie"
)

func TestEngineAllowlistPrecedence(t *testing.T) {
	t.Parallel()
	e := NewEngine(modeZeroIP, map[string]struct{}{"ads.example": {}}, map[string]struct{}{"ads.example": {}})
	d := e.Evaluate("ads.example.", queryTypeA)
	if d.Action != actionAllow {
		t.Fatalf("expected allow action, got %q", d.Action)
	}
	if d.Code != codePass {
		t.Fatalf("expected pass code, got %d", d.Code)
	}
}

func TestEngineZeroIPA(t *testing.T) {
	t.Parallel()
	e := NewEngine(modeZeroIP, nil, map[string]struct{}{"ads.example": {}})
	d := e.Evaluate("ads.example.", queryTypeA)
	if d.Action != actionBlock {
		t.Fatalf("expected block action, got %q", d.Action)
	}
	if d.Code != codeSyntheticIP {
		t.Fatalf("expected synthetic code, got %d", d.Code)
	}
	if d.IP != "0.0.0.0" {
		t.Fatalf("expected zero ip, got %q", d.IP)
	}
}

func TestEngineZeroIPAAAA(t *testing.T) {
	t.Parallel()
	e := NewEngine(modeZeroIP, nil, map[string]struct{}{"ads.example": {}})
	d := e.Evaluate("ads.example.", queryTypeAAAA)
	if d.IP != "::" {
		t.Fatalf("expected ipv6 zero, got %q", d.IP)
	}
}

func TestEngineZeroIPNonAddressType(t *testing.T) {
	t.Parallel()
	e := NewEngine(modeZeroIP, nil, map[string]struct{}{"ads.example": {}})
	d := e.Evaluate("ads.example.", queryTypeOther)
	if d.Code != codeNXDomain {
		t.Fatalf("expected nxdomain code, got %d", d.Code)
	}
}

func TestEngineNXDomainMode(t *testing.T) {
	t.Parallel()
	e := NewEngine(modeNXDomain, nil, map[string]struct{}{"ads.example": {}})
	d := e.Evaluate("ads.example.", queryTypeA)
	if d.Code != codeNXDomain {
		t.Fatalf("expected nxdomain code, got %d", d.Code)
	}
	if d.IP != "" {
		t.Fatalf("expected no synthetic ip, got %q", d.IP)
	}
}

func TestEnginePassThroughWhenNotListed(t *testing.T) {
	t.Parallel()
	e := NewEngine(modeZeroIP, nil, map[string]struct{}{"ads.example": {}})
	d := e.Evaluate("ok.example.", queryTypeA)
	if d.Action != actionAllow {
		t.Fatalf("expected allow action, got %q", d.Action)
	}
}

func TestEngineWildcardBlocksDomainAndSubdomain(t *testing.T) {
	t.Parallel()

	wildcard := blockytrie.NewTrie(blockytrie.SplitTLD)
	wildcard.Insert("blocked.example")

	e := NewEngineWithMatchers(modeZeroIP, matcherSet{}, matcherSet{wildcard: wildcard})

	for _, name := range []string{"blocked.example.", "sub.blocked.example."} {
		d := e.Evaluate(name, queryTypeA)
		if d.Action != actionBlock {
			t.Fatalf("%s: expected block action, got %q", name, d.Action)
		}
	}
}

func TestEngineRegexMatchingAndAllowlistPrecedence(t *testing.T) {
	t.Parallel()

	allowRe := regexp.MustCompile(`^allowed[0-9]+\.example$`)
	denyRe := regexp.MustCompile(`^(allowed[0-9]+|ads[0-9]+)\.example$`)

	e := NewEngineWithMatchers(
		modeZeroIP,
		matcherSet{regex: []*regexp.Regexp{allowRe}},
		matcherSet{regex: []*regexp.Regexp{denyRe}},
	)

	allowed := e.Evaluate("allowed42.example.", queryTypeA)
	if allowed.Action != actionAllow {
		t.Fatalf("expected allowlist regex to win, got %q", allowed.Action)
	}

	blocked := e.Evaluate("ads42.example.", queryTypeA)
	if blocked.Action != actionBlock {
		t.Fatalf("expected deny regex to block, got %q", blocked.Action)
	}
}
