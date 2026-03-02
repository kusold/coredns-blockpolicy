package e2e

import (
	"testing"

	"github.com/miekg/dns"
)

func TestE2E_AllowlistOverridesDenylist(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := writeTempList(t, "example.com")
	allowFile := writeTempList(t, "example.com")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		AllowFile: allowFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
	})
	udp := startServer(t, corefile)

	resp := exchange(t, udp, "example.com", dns.TypeA)

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
	// Should reach upstream (1.2.3.4), NOT be blocked (0.0.0.0).
	if got := a.A.String(); got != "1.2.3.4" {
		t.Errorf("expected upstream 1.2.3.4 (passthrough), got %s", got)
	}
}

func TestE2E_UnblockedDomain_PassesThrough(t *testing.T) {
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
	if got := a.A.String(); got != "1.2.3.4" {
		t.Errorf("expected upstream 1.2.3.4 (passthrough), got %s", got)
	}
}

func TestE2E_SelectiveBlocking(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := writeTempList(t, "a.com", "b.com")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
	})
	udp := startServer(t, corefile)

	// a.com and b.com should be blocked.
	for _, domain := range []string{"a.com", "b.com"} {
		resp := exchange(t, udp, domain, dns.TypeA)
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("%s: expected NOERROR, got %s", domain, dns.RcodeToString[resp.Rcode])
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("%s: expected 1 answer, got %d", domain, len(resp.Answer))
		}
		a, ok := resp.Answer[0].(*dns.A)
		if !ok {
			t.Fatalf("%s: expected A record, got %T", domain, resp.Answer[0])
		}
		if got := a.A.String(); got != "0.0.0.0" {
			t.Errorf("%s: expected 0.0.0.0 (blocked), got %s", domain, got)
		}
	}

	// c.com should pass through.
	resp := exchange(t, udp, "c.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("c.com: expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("c.com: expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("c.com: expected A record, got %T", resp.Answer[0])
	}
	if got := a.A.String(); got != "1.2.3.4" {
		t.Errorf("c.com: expected upstream 1.2.3.4 (passthrough), got %s", got)
	}
}
