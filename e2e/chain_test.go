package e2e

import (
	"testing"

	"github.com/miekg/dns"
)

func TestE2E_BlockedDoesNotReachUpstream(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := writeTempList(t, "ads.example.com")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
	})
	udp := startServer(t, corefile)

	resp := exchange(t, udp, "ads.example.com", dns.TypeA)

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answer[0])
	}
	// Must be 0.0.0.0 (blocked), NOT 1.2.3.4 (upstream).
	if got := a.A.String(); got != "0.0.0.0" {
		t.Errorf("expected 0.0.0.0 (blocked, not forwarded), got %s", got)
	}
}

func TestE2E_AllowedReachesUpstream(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := writeTempList(t, "ads.example.com")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
	})
	udp := startServer(t, corefile)

	resp := exchange(t, udp, "safe.example.com", dns.TypeA)

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answer[0])
	}
	// Must be 1.2.3.4 (upstream), NOT 0.0.0.0 (blocked).
	if got := a.A.String(); got != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4 (forwarded to upstream), got %s", got)
	}
}
