//go:build coredns

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

func (c *captureWriter) LocalAddr() net.Addr       { return &net.IPAddr{} }
func (c *captureWriter) RemoteAddr() net.Addr      { return &net.IPAddr{} }
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

var _ plugin.Handler = &noopNext{}
