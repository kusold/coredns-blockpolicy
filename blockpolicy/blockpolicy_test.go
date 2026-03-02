package blockpolicy

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

type noopNext struct {
	calls atomic.Int32
}

func (*noopNext) Name() string { return "noop" }

func (n *noopNext) ServeDNS(context.Context, dns.ResponseWriter, *dns.Msg) (int, error) {
	n.calls.Add(1)
	return dns.RcodeSuccess, nil
}

type captureWriter struct {
	msg *dns.Msg
}

func (c *captureWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}
func (c *captureWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 55300}
}
func (c *captureWriter) Close() error              { return nil }
func (c *captureWriter) TsigStatus() error         { return nil }
func (c *captureWriter) TsigTimersOnly(bool)       {}
func (c *captureWriter) Hijack()                   {}
func (c *captureWriter) Write([]byte) (int, error) { return 0, nil }
func (c *captureWriter) WriteMsg(m *dns.Msg) error { c.msg = m; return nil }

func TestZeroIPBlocksA(t *testing.T) {
	t.Parallel()
	cfg := &Config{PolicyName: "default", Policy: PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second}}
	next := &noopNext{}
	bp := New(next, cfg, nil, map[string]struct{}{"ads.example": {}})

	req := new(dns.Msg)
	req.SetQuestion("ads.example.", dns.TypeA)
	w := &captureWriter{}

	rcode, err := bp.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected success rcode, got %d", rcode)
	}
	if w.msg == nil || len(w.msg.Answer) != 1 {
		t.Fatalf("expected one answer")
	}
	a, ok := w.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record answer")
	}
	if got := a.A.String(); got != "0.0.0.0" {
		t.Fatalf("expected 0.0.0.0, got %s", got)
	}
	if next.calls.Load() != 0 {
		t.Fatalf("expected next plugin not to be called")
	}
}

func TestAllowlistWins(t *testing.T) {
	t.Parallel()
	cfg := &Config{PolicyName: "default", Policy: PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second}}
	next := &noopNext{}
	bp := New(next, cfg, map[string]struct{}{"ads.example": {}}, map[string]struct{}{"ads.example": {}})

	req := new(dns.Msg)
	req.SetQuestion("ads.example.", dns.TypeA)
	w := &captureWriter{}

	rcode, err := bp.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected success rcode, got %d", rcode)
	}
	if w.msg != nil {
		t.Fatalf("expected request to pass to next plugin")
	}
	if next.calls.Load() != 1 {
		t.Fatalf("expected next plugin to be called once")
	}
}

func TestZeroIPBlocksAAAA(t *testing.T) {
	t.Parallel()
	cfg := &Config{PolicyName: "default", Policy: PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second}}
	bp := New(&noopNext{}, cfg, nil, map[string]struct{}{"ads.example": {}})

	req := new(dns.Msg)
	req.SetQuestion("ads.example.", dns.TypeAAAA)
	w := &captureWriter{}

	rcode, err := bp.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected success rcode, got %d", rcode)
	}
	if w.msg == nil || len(w.msg.Answer) != 1 {
		t.Fatalf("expected one AAAA answer")
	}
	aaaa, ok := w.msg.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("expected AAAA answer")
	}
	if got := aaaa.AAAA.String(); got != "::" {
		t.Fatalf("expected ::, got %s", got)
	}
}

func TestZeroIPNonAddressTypeReturnsNXDomain(t *testing.T) {
	t.Parallel()
	cfg := &Config{PolicyName: "default", Policy: PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second}}
	bp := New(&noopNext{}, cfg, nil, map[string]struct{}{"ads.example": {}})

	req := new(dns.Msg)
	req.SetQuestion("ads.example.", dns.TypeTXT)
	w := &captureWriter{}

	rcode, err := bp.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Fatalf("expected nxdomain rcode, got %d", rcode)
	}
}

func TestNXDomainModeAlwaysNXDomain(t *testing.T) {
	t.Parallel()
	cfg := &Config{PolicyName: "default", Policy: PolicyConfig{Mode: modeNXDomain, TTL: 60 * time.Second}}
	bp := New(&noopNext{}, cfg, nil, map[string]struct{}{"ads.example": {}})

	req := new(dns.Msg)
	req.SetQuestion("ads.example.", dns.TypeA)
	w := &captureWriter{}

	rcode, err := bp.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Fatalf("expected nxdomain rcode, got %d", rcode)
	}
}

func TestEmptyQuestionPassesThrough(t *testing.T) {
	t.Parallel()
	cfg := &Config{PolicyName: "default", Policy: PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second}}
	next := &noopNext{}
	bp := New(next, cfg, nil, map[string]struct{}{"ads.example": {}})

	req := new(dns.Msg)
	w := &captureWriter{}

	_, err := bp.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if next.calls.Load() != 1 {
		t.Fatalf("expected next plugin call for empty question")
	}
}

func TestUnblockedDomainPassesThrough(t *testing.T) {
	t.Parallel()
	cfg := &Config{PolicyName: "default", Policy: PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second}}
	next := &noopNext{}
	bp := New(next, cfg, nil, map[string]struct{}{"ads.example": {}})

	req := new(dns.Msg)
	req.SetQuestion("ok.example.", dns.TypeA)
	w := &captureWriter{}

	_, err := bp.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if next.calls.Load() != 1 {
		t.Fatalf("expected next plugin call for unblocked domain")
	}
}

func TestBlockResponseInvalidIP(t *testing.T) {
	t.Parallel()
	cfg := &Config{PolicyName: "default", Policy: PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second}}
	bp := New(&noopNext{}, cfg, nil, nil)

	req := new(dns.Msg)
	req.SetQuestion("ads.example.", dns.TypeA)
	_, err := bp.blockResponse(req, Decision{Action: actionBlock, Code: codeSyntheticIP, IP: "not-an-ip", Mode: modeZeroIP})
	if err == nil {
		t.Fatalf("expected invalid synthetic ip to fail")
	}
}

var _ plugin.Handler = &noopNext{}
