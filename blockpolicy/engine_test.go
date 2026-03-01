package blockpolicy

import "testing"

func TestEngineAllowlistPrecedence(t *testing.T) {
	t.Parallel()
	e := NewEngine(modeZeroIP, map[string]struct{}{"ads.example": {}}, map[string]struct{}{"ads.example": {}})
	d := e.Evaluate("ads.example.", qtypeA)
	if d.Action != actionAllow {
		t.Fatalf("expected allow action, got %q", d.Action)
	}
	if d.RCode != rcodeSuccess {
		t.Fatalf("expected success rcode, got %d", d.RCode)
	}
}

func TestEngineZeroIPA(t *testing.T) {
	t.Parallel()
	e := NewEngine(modeZeroIP, nil, map[string]struct{}{"ads.example": {}})
	d := e.Evaluate("ads.example.", qtypeA)
	if d.Action != actionBlock {
		t.Fatalf("expected block action, got %q", d.Action)
	}
	if d.RCode != rcodeSuccess {
		t.Fatalf("expected success rcode, got %d", d.RCode)
	}
	if d.IP != "0.0.0.0" {
		t.Fatalf("expected zero ip, got %q", d.IP)
	}
}

func TestEngineZeroIPAAAA(t *testing.T) {
	t.Parallel()
	e := NewEngine(modeZeroIP, nil, map[string]struct{}{"ads.example": {}})
	d := e.Evaluate("ads.example.", qtypeAAAA)
	if d.IP != "::" {
		t.Fatalf("expected ipv6 zero, got %q", d.IP)
	}
}

func TestEngineZeroIPNonAddressType(t *testing.T) {
	t.Parallel()
	e := NewEngine(modeZeroIP, nil, map[string]struct{}{"ads.example": {}})
	d := e.Evaluate("ads.example.", 16)
	if d.RCode != rcodeNXDomain {
		t.Fatalf("expected nxdomain, got %d", d.RCode)
	}
}

func TestEngineNXDomainMode(t *testing.T) {
	t.Parallel()
	e := NewEngine(modeNXDomain, nil, map[string]struct{}{"ads.example": {}})
	d := e.Evaluate("ads.example.", qtypeA)
	if d.RCode != rcodeNXDomain {
		t.Fatalf("expected nxdomain, got %d", d.RCode)
	}
	if d.IP != "" {
		t.Fatalf("expected no synthetic ip, got %q", d.IP)
	}
}

func TestEnginePassThroughWhenNotListed(t *testing.T) {
	t.Parallel()
	e := NewEngine(modeZeroIP, nil, map[string]struct{}{"ads.example": {}})
	d := e.Evaluate("ok.example.", qtypeA)
	if d.Action != actionAllow {
		t.Fatalf("expected allow action, got %q", d.Action)
	}
}
