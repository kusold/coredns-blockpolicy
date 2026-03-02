package e2e

import (
	"testing"

	"github.com/miekg/dns"
)

func TestE2E_ZeroIP_BlocksA(t *testing.T) {
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
	if got := a.A.String(); got != "0.0.0.0" {
		t.Errorf("expected 0.0.0.0, got %s", got)
	}
}

func TestE2E_ZeroIP_BlocksAAAA(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := writeTempList(t, "ads.example.com")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
	})
	udp := startServer(t, corefile)

	resp := exchange(t, udp, "ads.example.com", dns.TypeAAAA)

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("expected AAAA record, got %T", resp.Answer[0])
	}
	if got := aaaa.AAAA.String(); got != "::" {
		t.Errorf("expected ::, got %s", got)
	}
}

func TestE2E_ZeroIP_NonAddressType_ReturnsNXDOMAIN(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := writeTempList(t, "ads.example.com")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
	})
	udp := startServer(t, corefile)

	resp := exchange(t, udp, "ads.example.com", dns.TypeTXT)

	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("expected no answers, got %d", len(resp.Answer))
	}
}

func TestE2E_NXDomain_BlocksA(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := writeTempList(t, "ads.example.com")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "nxdomain",
		Upstream:  upstream,
	})
	udp := startServer(t, corefile)

	resp := exchange(t, udp, "ads.example.com", dns.TypeA)

	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("expected no answers, got %d", len(resp.Answer))
	}
}

func TestE2E_NXDomain_BlocksAAAA(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := writeTempList(t, "ads.example.com")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "nxdomain",
		Upstream:  upstream,
	})
	udp := startServer(t, corefile)

	resp := exchange(t, udp, "ads.example.com", dns.TypeAAAA)

	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("expected no answers, got %d", len(resp.Answer))
	}
}

func TestE2E_TTL_InSyntheticResponse(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := writeTempList(t, "ads.example.com")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "zeroip",
		TTL:       "42s",
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
	if got := resp.Answer[0].Header().Ttl; got != 42 {
		t.Errorf("expected TTL 42, got %d", got)
	}
}
