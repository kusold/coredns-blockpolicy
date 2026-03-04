package blockpolicy

import (
	"context"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	benchmarkLatencySampleLimit = 50000
	benchmarkP50TargetNS        = int64(500000)
	benchmarkP99TargetNS        = int64(2000000)
)

type benchmarkQuery struct {
	name  string
	qtype QueryType
}

func BenchmarkEngineEvaluate_100K(b *testing.B) {
	benchmarkEngineEvaluate(b, 100000)
}

func BenchmarkEngineEvaluate_1M(b *testing.B) {
	benchmarkEngineEvaluate(b, 1000000)
}

func BenchmarkServeDNS_AllowDirect_100K(b *testing.B) {
	benchmarkServeDNS(b, 100000, benchmarkServeDNSMode{
		name:             "allow_direct",
		queryName:        "allowed.bench.test.",
		qtype:            dns.TypeA,
		enableDeepCNAME:  false,
		enableResponseIP: false,
		next:             &benchmarkNextHandler{},
	})
}

func BenchmarkServeDNS_AllowDirect_1M(b *testing.B) {
	benchmarkServeDNS(b, 1000000, benchmarkServeDNSMode{
		name:             "allow_direct",
		queryName:        "allowed.bench.test.",
		qtype:            dns.TypeA,
		enableDeepCNAME:  false,
		enableResponseIP: false,
		next:             &benchmarkNextHandler{},
	})
}

func BenchmarkServeDNS_AllowDeepChecks_100K(b *testing.B) {
	benchmarkServeDNS(b, 100000, benchmarkServeDNSMode{
		name:             "allow_deep_checks",
		queryName:        "safe.bench.test.",
		qtype:            dns.TypeA,
		enableDeepCNAME:  true,
		enableResponseIP: true,
		next: &benchmarkNextHandler{
			writeReply:   true,
			replyAnswers: benchmarkDefaultAnswers(),
		},
	})
}

func BenchmarkServeDNS_AllowDeepChecks_1M(b *testing.B) {
	benchmarkServeDNS(b, 1000000, benchmarkServeDNSMode{
		name:             "allow_deep_checks",
		queryName:        "safe.bench.test.",
		qtype:            dns.TypeA,
		enableDeepCNAME:  true,
		enableResponseIP: true,
		next: &benchmarkNextHandler{
			writeReply:   true,
			replyAnswers: benchmarkDefaultAnswers(),
		},
	})
}

func BenchmarkServeDNS_Blocked_100K(b *testing.B) {
	benchmarkServeDNS(b, 100000, benchmarkServeDNSMode{
		name:             "blocked",
		queryName:        benchmarkDomain(42) + ".",
		qtype:            dns.TypeA,
		enableDeepCNAME:  false,
		enableResponseIP: false,
		next:             &benchmarkNextHandler{},
	})
}

func BenchmarkServeDNS_Blocked_1M(b *testing.B) {
	benchmarkServeDNS(b, 1000000, benchmarkServeDNSMode{
		name:             "blocked",
		queryName:        benchmarkDomain(42) + ".",
		qtype:            dns.TypeA,
		enableDeepCNAME:  false,
		enableResponseIP: false,
		next:             &benchmarkNextHandler{},
	})
}

func benchmarkEngineEvaluate(b *testing.B, entries int) {
	deny := make(map[string]struct{}, entries)
	blockedNames := make([]string, 0, 2048)
	for i := 0; i < entries; i++ {
		domain := benchmarkDomain(i)
		deny[domain] = struct{}{}
		if i < cap(blockedNames) {
			blockedNames = append(blockedNames, domain)
		}
	}

	engine := NewEngine(modeZeroIP, nil, deny)
	queries := buildBenchmarkQueries(blockedNames)
	if len(queries) == 0 {
		b.Fatal("expected benchmark query set")
	}

	latencies := make([]int64, 0, sampleLimit(b.N, benchmarkLatencySampleLimit))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		query := queries[i%len(queries)]
		start := time.Now()
		_ = engine.Evaluate(query.name, query.qtype)
		if len(latencies) < cap(latencies) {
			latencies = append(latencies, time.Since(start).Nanoseconds())
		}
	}
	b.StopTimer()

	reportAndCheckPercentiles(b, latencies)
}

func buildBenchmarkQueries(blocked []string) []benchmarkQuery {
	if len(blocked) == 0 {
		return nil
	}

	queries := make([]benchmarkQuery, 0, len(blocked)*2)
	for i, domain := range blocked {
		queries = append(queries, benchmarkQuery{name: domain + ".", qtype: benchmarkQueryType(i)})
		queries = append(queries, benchmarkQuery{name: "allowed-" + strconv.Itoa(i) + ".bench.test.", qtype: benchmarkQueryType(i + 1)})
	}
	return queries
}

func benchmarkDomain(i int) string {
	return "blocked-" + strconv.Itoa(i) + ".bench.test"
}

func benchmarkQueryType(i int) QueryType {
	switch i % 3 {
	case 0:
		return queryTypeA
	case 1:
		return queryTypeAAAA
	default:
		return queryTypeOther
	}
}

func reportAndCheckPercentiles(b *testing.B, samples []int64) {
	b.Helper()
	if len(samples) == 0 {
		return
	}

	p50 := percentile(samples, 50)
	p99 := percentile(samples, 99)
	b.ReportMetric(float64(p50), "p50_ns/op")
	b.ReportMetric(float64(p99), "p99_ns/op")

	if os.Getenv("BLOCKPOLICY_BENCH_ASSERT") != "1" {
		return
	}

	if p50 > benchmarkP50TargetNS {
		b.Fatalf("p50 latency %d ns exceeds target %d ns", p50, benchmarkP50TargetNS)
	}
	if p99 > benchmarkP99TargetNS {
		b.Fatalf("p99 latency %d ns exceeds target %d ns", p99, benchmarkP99TargetNS)
	}
}

func percentile(samples []int64, p float64) int64 {
	sorted := append([]int64(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})
	if len(sorted) == 1 {
		return sorted[0]
	}

	rank := int(math.Ceil((p/100.0)*float64(len(sorted)))) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}

func sampleLimit(current, max int) int {
	if current < max {
		return current
	}
	return max
}

type benchmarkServeDNSMode struct {
	name             string
	queryName        string
	qtype            uint16
	enableDeepCNAME  bool
	enableResponseIP bool
	next             *benchmarkNextHandler
}

func benchmarkServeDNS(b *testing.B, entries int, mode benchmarkServeDNSMode) {
	deny := make(map[string]struct{}, entries)
	for i := 0; i < entries; i++ {
		deny[benchmarkDomain(i)] = struct{}{}
	}

	if mode.next == nil {
		mode.next = &benchmarkNextHandler{}
	}
	cfg := &Config{
		PolicyName: "bench",
		Policy: PolicyConfig{
			Mode: modeZeroIP,
			TTL:  60 * time.Second,
		},
		Matching: MatchingConfig{
			Exact:           true,
			Wildcard:        true,
			Regex:           true,
			HostsFormat:     true,
			DeepCNAME:       mode.enableDeepCNAME,
			ResponseIPLists: mode.enableResponseIP,
		},
		matchingConfigured: true,
	}
	bp := testBlockPolicy(mode.next, cfg, matcherSet{}, matcherSet{exact: deny})

	req := newDNSRequest(mode.queryName, mode.qtype)
	writer := &benchmarkResponseWriter{}
	ctx := context.Background()
	latencies := make([]int64, 0, sampleLimit(b.N, benchmarkLatencySampleLimit))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		if _, err := bp.ServeDNS(ctx, writer, req); err != nil {
			b.Fatalf("%s: ServeDNS error: %v", mode.name, err)
		}
		if len(latencies) < cap(latencies) {
			latencies = append(latencies, time.Since(start).Nanoseconds())
		}
	}
	b.StopTimer()

	reportAndCheckPercentiles(b, latencies)
}

type benchmarkNextHandler struct {
	// Dedicated benchmark handler avoids test-helper counters on the hot path.
	writeReply   bool
	replyAnswers []benchmarkRRSpec
}

func (*benchmarkNextHandler) Name() string { return "bench-next" }

func (h *benchmarkNextHandler) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if !h.writeReply {
		return dns.RcodeSuccess, nil
	}
	reply := new(dns.Msg)
	reply.SetReply(r)
	reply.Answer = make([]dns.RR, 0, len(h.replyAnswers))
	for _, spec := range h.replyAnswers {
		reply.Answer = append(reply.Answer, spec.toRR())
	}
	if err := w.WriteMsg(reply); err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeSuccess, nil
}

type benchmarkRRSpec struct {
	name string
	kind uint16
	data string
}

func (s benchmarkRRSpec) toRR() dns.RR {
	switch s.kind {
	case dns.TypeCNAME:
		return &dns.CNAME{
			Hdr:    dns.RR_Header{Name: s.name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: s.data,
		}
	case dns.TypeAAAA:
		return &dns.AAAA{
			Hdr:  dns.RR_Header{Name: s.name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.ParseIP(s.data),
		}
	default:
		return &dns.A{
			Hdr: dns.RR_Header{Name: s.name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(s.data).To4(),
		}
	}
}

func benchmarkDefaultAnswers() []benchmarkRRSpec {
	return []benchmarkRRSpec{
		{
			name: "safe.bench.test.",
			kind: dns.TypeCNAME,
			data: "content.bench.test.",
		},
		{
			name: "content.bench.test.",
			kind: dns.TypeA,
			data: "203.0.113.10",
		},
		{
			name: "content.bench.test.",
			kind: dns.TypeAAAA,
			data: "2001:db8::10",
		},
	}
}

type benchmarkResponseWriter struct {
	noopResponseWriter
}

func newDNSRequest(name string, qtype uint16) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	return req
}
