package e2e

import (
	"testing"

	"github.com/miekg/dns"
)

func TestE2E_WildcardBlocking(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := writeTempList(t, "*.blocked.example")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
	})
	udp := startServer(t, corefile)

	for _, domain := range []string{"blocked.example", "sub.blocked.example"} {
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
			t.Fatalf("%s: expected blocked 0.0.0.0, got %s", domain, got)
		}
	}
}

func TestE2E_RegexBlocking(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := writeTempList(t, "/^ads[0-9]+\\.example$/")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
	})
	udp := startServer(t, corefile)

	blocked := exchange(t, udp, "ads42.example", dns.TypeA)
	if blocked.Rcode != dns.RcodeSuccess {
		t.Fatalf("ads42.example: expected NOERROR, got %s", dns.RcodeToString[blocked.Rcode])
	}
	if len(blocked.Answer) != 1 {
		t.Fatalf("ads42.example: expected 1 answer, got %d", len(blocked.Answer))
	}
	a, ok := blocked.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("ads42.example: expected A record, got %T", blocked.Answer[0])
	}
	if got := a.A.String(); got != "0.0.0.0" {
		t.Fatalf("ads42.example: expected blocked 0.0.0.0, got %s", got)
	}

	allowed := exchange(t, udp, "ads.example", dns.TypeA)
	if allowed.Rcode != dns.RcodeSuccess {
		t.Fatalf("ads.example: expected NOERROR, got %s", dns.RcodeToString[allowed.Rcode])
	}
	if len(allowed.Answer) != 1 {
		t.Fatalf("ads.example: expected 1 answer, got %d", len(allowed.Answer))
	}
	allowedA, ok := allowed.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("ads.example: expected A record, got %T", allowed.Answer[0])
	}
	if got := allowedA.A.String(); got != "1.2.3.4" {
		t.Fatalf("ads.example: expected upstream 1.2.3.4, got %s", got)
	}
}
