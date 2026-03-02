package e2e

import (
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/metrics"
	coretest "github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

// Metrics tests run serially (no t.Parallel) because Prometheus counters are
// global singletons. Each test starts a fresh server to minimise interference.

func TestE2E_Metrics_BlockedCounter(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := writeTempList(t, "ads.example.com")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
		PromAddr:  "127.0.0.1:0",
	})
	udp := startServer(t, corefile)

	// Allow prometheus listener to be ready.
	time.Sleep(100 * time.Millisecond)
	promAddr := metrics.ListenAddr

	// Send a query that should be blocked.
	resp := exchange(t, udp, "ads.example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}

	got := coretest.ScrapeMetricAsInt(promAddr, "coredns_blockpolicy_blocked_total", "denylist", -1)
	if got < 1 {
		t.Errorf("expected coredns_blockpolicy_blocked_total{reason=denylist} >= 1, got %d", got)
	}
}

func TestE2E_Metrics_AllowedPassthrough(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := writeTempList(t, "ads.example.com")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
		PromAddr:  "127.0.0.1:0",
	})
	udp := startServer(t, corefile)

	time.Sleep(100 * time.Millisecond)
	promAddr := metrics.ListenAddr

	// Send a query that should pass through.
	resp := exchange(t, udp, "safe.example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}

	got := coretest.ScrapeMetricAsInt(promAddr, "coredns_blockpolicy_allowed_total", "passthrough", -1)
	if got < 1 {
		t.Errorf("expected coredns_blockpolicy_allowed_total{reason=passthrough} >= 1, got %d", got)
	}
}

func TestE2E_Metrics_AllowlistReason(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := writeTempList(t, "example.com")
	allowFile := writeTempList(t, "example.com")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		AllowFile: allowFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
		PromAddr:  "127.0.0.1:0",
	})
	udp := startServer(t, corefile)

	time.Sleep(100 * time.Millisecond)
	promAddr := metrics.ListenAddr

	// Send a query for a domain in both allow and deny — allowlist wins.
	resp := exchange(t, udp, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}

	got := coretest.ScrapeMetricAsInt(promAddr, "coredns_blockpolicy_allowed_total", "allowlist", -1)
	if got < 1 {
		t.Errorf("expected coredns_blockpolicy_allowed_total{reason=allowlist} >= 1, got %d", got)
	}
}

func TestE2E_Metrics_QueriesTotal(t *testing.T) {
	upstream := startUpstream(t)
	denyFile := writeTempList(t, "ads.example.com")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
		PromAddr:  "127.0.0.1:0",
	})
	udp := startServer(t, corefile)

	time.Sleep(100 * time.Millisecond)
	promAddr := metrics.ListenAddr

	// Send 3 queries: 2 blocked, 1 allowed.
	exchange(t, udp, "ads.example.com", dns.TypeA)
	exchange(t, udp, "ads.example.com", dns.TypeAAAA)
	exchange(t, udp, "safe.example.com", dns.TypeA)

	got := coretest.ScrapeMetricAsInt(promAddr, "coredns_blockpolicy_queries_total", "", -1)
	if got < 3 {
		t.Errorf("expected coredns_blockpolicy_queries_total >= 3, got %d", got)
	}
}
