package blockpolicy

import "testing"

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
