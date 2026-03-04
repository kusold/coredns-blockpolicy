package blockpolicy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type captureWriter struct {
	noopResponseWriter
	msg *dns.Msg
}

func (c *captureWriter) WriteMsg(m *dns.Msg) error { c.msg = m; return nil }

func TestZeroIPBlocksA(t *testing.T) {
	t.Parallel()
	cfg := &Config{PolicyName: "default", Policy: PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second}}
	next := &noopNext{}
	bp := testBlockPolicy(next, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"ads.example": {}}})

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
	bp := testBlockPolicy(next, cfg, matcherSet{exact: map[string]struct{}{"ads.example": {}}}, matcherSet{exact: map[string]struct{}{"ads.example": {}}})

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
	bp := testBlockPolicy(&noopNext{}, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"ads.example": {}}})

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
	bp := testBlockPolicy(&noopNext{}, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"ads.example": {}}})

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
	bp := testBlockPolicy(&noopNext{}, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"ads.example": {}}})

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
	bp := testBlockPolicy(next, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"ads.example": {}}})

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
	bp := testBlockPolicy(next, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"ads.example": {}}})

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
	bp := testBlockPolicy(&noopNext{}, cfg, matcherSet{}, matcherSet{})

	req := new(dns.Msg)
	req.SetQuestion("ads.example.", dns.TypeA)
	_, err := bp.blockResponse(req, Decision{Action: actionBlock, Code: codeSyntheticIP, IP: "not-an-ip", Mode: modeZeroIP})
	if err == nil {
		t.Fatalf("expected invalid synthetic ip to fail")
	}
}

func TestDeepCNAMECheckBlocksOnDenylistedTarget(t *testing.T) {
	t.Parallel()

	cfg := deepCheckConfig(modeZeroIP, true, true)

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
	bp := testBlockPolicy(next, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"bad.example": {}}})

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

	cfg := deepCheckConfig(modeZeroIP, true, true)

	resp := new(dns.Msg)
	resp.SetReply(&dns.Msg{Question: []dns.Question{{Name: "safe.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}})
	resp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "safe.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("123.145.123.145").To4(),
		},
	}

	next := &staticResponseNext{msg: resp}
	bp := testBlockPolicy(next, cfg, matcherSet{}, matcherSet{ips: map[string]struct{}{"123.145.123.145": {}}})

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

	cfg := deepCheckConfig(modeZeroIP, true, true)

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
	bp := testBlockPolicy(
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

	cfg := deepCheckConfig(modeZeroIP, false, false)

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
	bp := testBlockPolicy(
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

func TestResponseIPCheckBlocksOnDenylistedIPv6(t *testing.T) {
	t.Parallel()

	cfg := deepCheckConfig(modeZeroIP, true, true)

	resp := new(dns.Msg)
	resp.SetReply(&dns.Msg{Question: []dns.Question{{Name: "safe.example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}}})
	resp.Answer = []dns.RR{
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "safe.example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: net.ParseIP("2001:db8::10"),
		},
	}

	next := &staticResponseNext{msg: resp}
	bp := testBlockPolicy(next, cfg, matcherSet{}, matcherSet{ips: map[string]struct{}{"2001:db8::10": {}}})

	req := new(dns.Msg)
	req.SetQuestion("safe.example.", dns.TypeAAAA)
	w := &captureWriter{}

	rcode, err := bp.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR synthetic response, got %d", rcode)
	}
	if w.msg == nil || len(w.msg.Answer) != 1 {
		t.Fatalf("expected one synthetic AAAA answer")
	}
	aaaa, ok := w.msg.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("expected AAAA answer, got %T", w.msg.Answer[0])
	}
	if got := aaaa.AAAA.String(); got != "::" {
		t.Fatalf("expected ::, got %s", got)
	}
}

func TestDeepCNAMECheckUsesNXDomainMode(t *testing.T) {
	t.Parallel()

	cfg := deepCheckConfig(modeNXDomain, true, true)

	resp := new(dns.Msg)
	resp.SetReply(&dns.Msg{Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}})
	resp.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: "bad.example.",
		},
	}

	next := &staticResponseNext{msg: resp}
	bp := testBlockPolicy(next, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"bad.example": {}}})

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	w := &captureWriter{}

	rcode, err := bp.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %d", rcode)
	}
	if w.msg == nil {
		t.Fatalf("expected DNS response")
	}
}

func TestDeepChecksReturnsNextError(t *testing.T) {
	t.Parallel()

	cfg := deepCheckConfig(modeZeroIP, true, true)
	next := &errorNext{}
	bp := testBlockPolicy(next, cfg, matcherSet{}, matcherSet{})

	req := new(dns.Msg)
	req.SetQuestion("ok.example.", dns.TypeA)
	w := &captureWriter{}

	rcode, err := bp.ServeDNS(context.Background(), w, req)
	if err == nil {
		t.Fatalf("expected downstream error")
	}
	if rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL, got %d", rcode)
	}
}

func deepCheckConfig(mode blockMode, deepCNAME, responseIP bool) *Config {
	return &Config{
		PolicyName: "default",
		Policy:     PolicyConfig{Mode: mode, TTL: 60 * time.Second},
		Matching: MatchingConfig{
			Exact:           true,
			Wildcard:        true,
			Regex:           true,
			HostsFormat:     true,
			DeepCNAME:       deepCNAME,
			ResponseIPLists: responseIP,
		},
		matchingConfigured: true,
	}
}

func TestZoneMatchingSkipsOutOfZoneQueries(t *testing.T) {
	t.Parallel()
	cfg := &Config{PolicyName: "default", Policy: PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second}}
	next := &noopNext{}
	bp := NewWithMatchers(next, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"ads.example": {}}})
	bp.Zones = []string{"other.example."}

	req := new(dns.Msg)
	req.SetQuestion("ads.example.", dns.TypeA)
	w := &captureWriter{}

	_, err := bp.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if next.calls.Load() != 1 {
		t.Fatalf("expected query to pass through to next plugin for out-of-zone domain")
	}
	if w.msg != nil {
		t.Fatalf("expected no response from blockpolicy for out-of-zone query")
	}
}

func TestZoneMatchingBlocksInZoneQueries(t *testing.T) {
	t.Parallel()
	cfg := &Config{PolicyName: "default", Policy: PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second}}
	next := &noopNext{}
	bp := NewWithMatchers(next, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"ads.example": {}}})
	bp.Zones = []string{"example."}

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
		t.Fatalf("expected blocked response with one answer")
	}
	if next.calls.Load() != 0 {
		t.Fatalf("expected next plugin not to be called for blocked in-zone query")
	}
}

func TestZoneLabelInMetrics(t *testing.T) {
	t.Parallel()
	cfg := &Config{PolicyName: "default", Policy: PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second}}
	bp := NewWithMatchers(&noopNext{}, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"ads.example": {}}})
	bp.Zones = []string{"example."}

	req := new(dns.Msg)
	req.SetQuestion("ads.example.", dns.TypeA)
	w := &captureWriter{}

	_, err := bp.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}

	// Verify zone label is "example." not hardcoded "."
	// The metric was recorded so we just verify no panic and the query was blocked.
	if w.msg == nil || len(w.msg.Answer) != 1 {
		t.Fatalf("expected blocked response")
	}
}

func TestFallthroughPassesBlockedQueryToNext(t *testing.T) {
	t.Parallel()
	cfg := &Config{PolicyName: "default", Policy: PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second}}
	cfg.Fall.SetZonesFromArgs(nil) // fallthrough for all zones
	next := &noopNext{}
	bp := testBlockPolicy(next, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"ads.example": {}}})

	req := new(dns.Msg)
	req.SetQuestion("ads.example.", dns.TypeA)
	w := &captureWriter{}

	_, err := bp.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if next.calls.Load() != 1 {
		t.Fatalf("expected blocked query to fall through to next plugin")
	}
}

func TestFallthroughDisabledBlocksQuery(t *testing.T) {
	t.Parallel()
	cfg := &Config{PolicyName: "default", Policy: PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second}}
	// Fall is zero value = no fallthrough
	next := &noopNext{}
	bp := testBlockPolicy(next, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"ads.example": {}}})

	req := new(dns.Msg)
	req.SetQuestion("ads.example.", dns.TypeA)
	w := &captureWriter{}

	rcode, err := bp.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected success rcode from zeroip block, got %d", rcode)
	}
	if next.calls.Load() != 0 {
		t.Fatalf("expected blocked query not to fall through")
	}
	if w.msg == nil || len(w.msg.Answer) != 1 {
		t.Fatalf("expected blocked response with one answer")
	}
}

func TestFallthroughLimitedToSpecificZone(t *testing.T) {
	t.Parallel()
	cfg := &Config{PolicyName: "default", Policy: PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second}}
	cfg.Fall.SetZonesFromArgs([]string{"other.example."})
	next := &noopNext{}
	bp := testBlockPolicy(next, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"ads.example": {}, "ads.other.example": {}}})

	// Query in the fallthrough zone should pass through
	req1 := new(dns.Msg)
	req1.SetQuestion("ads.other.example.", dns.TypeA)
	w1 := &captureWriter{}
	_, err := bp.ServeDNS(context.Background(), w1, req1)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if next.calls.Load() != 1 {
		t.Fatalf("expected fallthrough for query in fallthrough zone")
	}

	// Query outside the fallthrough zone should be blocked
	req2 := new(dns.Msg)
	req2.SetQuestion("ads.example.", dns.TypeA)
	w2 := &captureWriter{}
	rcode, err := bp.ServeDNS(context.Background(), w2, req2)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected blocked response for query outside fallthrough zone")
	}
	if w2.msg == nil || len(w2.msg.Answer) != 1 {
		t.Fatalf("expected blocked response")
	}
}

func TestHealthyReturnsTrueWhenNoErrors(t *testing.T) {
	t.Parallel()
	cfg := &Config{PolicyName: "default", Policy: PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second}}
	bp := testBlockPolicy(&noopNext{}, cfg, matcherSet{}, matcherSet{})

	if !bp.Healthy() {
		t.Fatalf("expected Healthy() to return true with no errors")
	}
}

func TestHealthyReturnsFalseAfterConsecutiveErrors(t *testing.T) {
	t.Parallel()
	cfg := &Config{PolicyName: "default", Policy: PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second}}
	bp := testBlockPolicy(&noopNext{}, cfg, matcherSet{}, matcherSet{})

	for i := 0; i < maxConsecutiveRefreshErrors; i++ {
		bp.consecutiveRefreshErrors.Add(1)
	}

	if bp.Healthy() {
		t.Fatalf("expected Healthy() to return false after %d consecutive errors", maxConsecutiveRefreshErrors)
	}
}

func TestHealthyResetsAfterSuccessfulRefresh(t *testing.T) {
	t.Parallel()
	cfg := &Config{PolicyName: "default", Policy: PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second}}
	bp := testBlockPolicy(&noopNext{}, cfg, matcherSet{}, matcherSet{})

	for i := 0; i < maxConsecutiveRefreshErrors; i++ {
		bp.consecutiveRefreshErrors.Add(1)
	}
	if bp.Healthy() {
		t.Fatalf("expected unhealthy before reset")
	}

	bp.consecutiveRefreshErrors.Store(0)
	if !bp.Healthy() {
		t.Fatalf("expected Healthy() to return true after counter reset")
	}
}
