package blockpolicy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

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
	bp := NewWithMatchers(next, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"ads.example": {}}})

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
	bp := NewWithMatchers(next, cfg, matcherSet{exact: map[string]struct{}{"ads.example": {}}}, matcherSet{exact: map[string]struct{}{"ads.example": {}}})

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
	bp := NewWithMatchers(&noopNext{}, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"ads.example": {}}})

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
	bp := NewWithMatchers(&noopNext{}, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"ads.example": {}}})

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
	bp := NewWithMatchers(&noopNext{}, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"ads.example": {}}})

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
	bp := NewWithMatchers(next, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"ads.example": {}}})

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
	bp := NewWithMatchers(next, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"ads.example": {}}})

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
	bp := NewWithMatchers(&noopNext{}, cfg, matcherSet{}, matcherSet{})

	req := new(dns.Msg)
	req.SetQuestion("ads.example.", dns.TypeA)
	_, err := bp.blockResponse(req, Decision{Action: actionBlock, Code: codeSyntheticIP, IP: "not-an-ip", Mode: modeZeroIP})
	if err == nil {
		t.Fatalf("expected invalid synthetic ip to fail")
	}
}

func TestDeepCNAMECheckBlocksOnDenylistedTarget(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		PolicyName: "default",
		Policy:     PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second},
		Matching: MatchingConfig{
			Exact:           true,
			Wildcard:        true,
			Regex:           true,
			HostsFormat:     true,
			DeepCNAME:       true,
			ResponseIPLists: true,
		},
		matchingConfigured: true,
	}

	resp := new(dns.Msg)
	resp.SetReply(&dns.Msg{Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}})
	resp.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: "bad.example.",
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "bad.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("9.9.9.9").To4(),
		},
	}

	next := &staticResponseNext{msg: resp}
	bp := NewWithMatchers(next, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"bad.example": {}}})

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	w := &captureWriter{}

	rcode, err := bp.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR synthetic response, got %d", rcode)
	}
	if w.msg == nil || len(w.msg.Answer) != 1 {
		t.Fatalf("expected one synthetic A answer")
	}
	a, ok := w.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A answer, got %T", w.msg.Answer[0])
	}
	if got := a.A.String(); got != "0.0.0.0" {
		t.Fatalf("expected 0.0.0.0, got %s", got)
	}
	if next.calls.Load() != 1 {
		t.Fatalf("expected next plugin to be called once")
	}
}

func TestResponseIPCheckBlocksOnDenylistedIP(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		PolicyName: "default",
		Policy:     PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second},
		Matching: MatchingConfig{
			Exact:           true,
			Wildcard:        true,
			Regex:           true,
			HostsFormat:     true,
			DeepCNAME:       true,
			ResponseIPLists: true,
		},
		matchingConfigured: true,
	}

	resp := new(dns.Msg)
	resp.SetReply(&dns.Msg{Question: []dns.Question{{Name: "safe.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}})
	resp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "safe.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("123.145.123.145").To4(),
		},
	}

	next := &staticResponseNext{msg: resp}
	bp := NewWithMatchers(next, cfg, matcherSet{}, matcherSet{ips: map[string]struct{}{"123.145.123.145": {}}})

	req := new(dns.Msg)
	req.SetQuestion("safe.example.", dns.TypeA)
	w := &captureWriter{}

	rcode, err := bp.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR synthetic response, got %d", rcode)
	}
	if w.msg == nil || len(w.msg.Answer) != 1 {
		t.Fatalf("expected one synthetic A answer")
	}
	a, ok := w.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A answer, got %T", w.msg.Answer[0])
	}
	if got := a.A.String(); got != "0.0.0.0" {
		t.Fatalf("expected 0.0.0.0, got %s", got)
	}
	if next.calls.Load() != 1 {
		t.Fatalf("expected next plugin to be called once")
	}
}

func TestDeepChecksAllowlistPrecedenceOnResponseEntries(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		PolicyName: "default",
		Policy:     PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second},
		Matching: MatchingConfig{
			Exact:           true,
			Wildcard:        true,
			Regex:           true,
			HostsFormat:     true,
			DeepCNAME:       true,
			ResponseIPLists: true,
		},
		matchingConfigured: true,
	}

	resp := new(dns.Msg)
	resp.SetReply(&dns.Msg{Question: []dns.Question{{Name: "safe.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}})
	resp.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "safe.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: "bad.example.",
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "bad.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("123.145.123.145").To4(),
		},
	}

	next := &staticResponseNext{msg: resp}
	bp := NewWithMatchers(
		next,
		cfg,
		matcherSet{exact: map[string]struct{}{"bad.example": {}}, ips: map[string]struct{}{"123.145.123.145": {}}},
		matcherSet{exact: map[string]struct{}{"bad.example": {}}, ips: map[string]struct{}{"123.145.123.145": {}}},
	)

	req := new(dns.Msg)
	req.SetQuestion("safe.example.", dns.TypeA)
	w := &captureWriter{}

	rcode, err := bp.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR passthrough, got %d", rcode)
	}
	if w.msg == nil || len(w.msg.Answer) != 2 {
		t.Fatalf("expected passthrough response from next plugin")
	}
	a, ok := w.msg.Answer[1].(*dns.A)
	if !ok {
		t.Fatalf("expected passthrough A answer, got %T", w.msg.Answer[1])
	}
	if got := a.A.String(); got != "123.145.123.145" {
		t.Fatalf("expected upstream response IP, got %s", got)
	}
	if next.calls.Load() != 1 {
		t.Fatalf("expected next plugin to be called once")
	}
}

func TestDeepChecksCanBeDisabled(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		PolicyName: "default",
		Policy:     PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second},
		Matching: MatchingConfig{
			Exact:           true,
			Wildcard:        true,
			Regex:           true,
			HostsFormat:     true,
			DeepCNAME:       false,
			ResponseIPLists: false,
		},
		matchingConfigured: true,
	}

	resp := new(dns.Msg)
	resp.SetReply(&dns.Msg{Question: []dns.Question{{Name: "safe.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}})
	resp.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "safe.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: "bad.example.",
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "bad.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("123.145.123.145").To4(),
		},
	}

	next := &staticResponseNext{msg: resp}
	bp := NewWithMatchers(
		next,
		cfg,
		matcherSet{},
		matcherSet{exact: map[string]struct{}{"bad.example": {}}, ips: map[string]struct{}{"123.145.123.145": {}}},
	)

	req := new(dns.Msg)
	req.SetQuestion("safe.example.", dns.TypeA)
	w := &captureWriter{}

	rcode, err := bp.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR passthrough, got %d", rcode)
	}
	if w.msg == nil || len(w.msg.Answer) != 2 {
		t.Fatalf("expected passthrough response from next plugin")
	}
	if next.calls.Load() != 1 {
		t.Fatalf("expected next plugin to be called once")
	}
}
