package e2e

import (
	"testing"

	"github.com/miekg/dns"
)

func TestE2E_HostsFormat(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := testdataPath(t, "hosts_deny.txt")

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
	if got := a.A.String(); got != "0.0.0.0" {
		t.Errorf("expected 0.0.0.0 (blocked), got %s", got)
	}
}

func TestE2E_HostsFormat_MultiDomain(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := testdataPath(t, "hosts_deny.txt")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
	})
	udp := startServer(t, corefile)

	// hosts_deny.txt has "0.0.0.0 a.example.com b.example.com" on one line
	for _, domain := range []string{"a.example.com", "b.example.com"} {
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
}

func TestE2E_HostsFormat_IPv6Prefix(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := testdataPath(t, "hosts_deny.txt")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
	})
	udp := startServer(t, corefile)

	// hosts_deny.txt has ":: tracker.example.com"
	resp := exchange(t, udp, "tracker.example.com", dns.TypeA)

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
	if got := a.A.String(); got != "0.0.0.0" {
		t.Errorf("expected 0.0.0.0 (blocked), got %s", got)
	}
}

func TestE2E_Comments_Ignored(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := writeTempFile(t, "ads.com # inline comment\n# full line comment\ntracker.com\n")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
	})
	udp := startServer(t, corefile)

	for _, domain := range []string{"ads.com", "tracker.com"} {
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
}

func TestE2E_EmptyDenyList(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := writeTempFile(t, "")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
	})
	udp := startServer(t, corefile)

	resp := exchange(t, udp, "anything.com", dns.TypeA)

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

func TestE2E_CaseInsensitive(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := writeTempList(t, "ads.example.com")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
	})
	udp := startServer(t, corefile)

	// Query with mixed case — should still match the lowercase entry.
	resp := exchange(t, udp, "ADS.Example.COM", dns.TypeA)

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
	if got := a.A.String(); got != "0.0.0.0" {
		t.Errorf("expected 0.0.0.0 (blocked despite case difference), got %s", got)
	}
}

func TestE2E_TrailingDot_Normalization(t *testing.T) {
	upstream := startUpstream(t)
	// List file has domain WITHOUT trailing dot.
	denyFile := writeTempList(t, "ads.example.com")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
	})
	udp := startServer(t, corefile)

	// DNS queries always have trailing dot (FQDN). Should still match.
	resp := exchange(t, udp, "ads.example.com.", dns.TypeA)

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
	if got := a.A.String(); got != "0.0.0.0" {
		t.Errorf("expected 0.0.0.0 (blocked despite trailing dot), got %s", got)
	}
}
