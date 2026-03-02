package blockpolicy

// Package blockpolicy implements a CoreDNS plugin for policy-driven DNS blocking.
// The package includes setup parsing, request handling, refresh lifecycle, metrics,
// and matcher logic (exact, wildcard, regex, and response-IP).
//
// Milestone 5 developer workflows:
//   - Run matcher benchmarks:
//     go test ./blockpolicy -run=^$ -bench='BenchmarkEngineEvaluate_(100K|1M)$' -benchmem
//   - Run end-to-end plugin benchmarks:
//     go test ./blockpolicy -run=^$ -bench='BenchmarkServeDNS_.*_(100K|1M)$' -benchmem
//   - Optionally assert p50/p99 latency targets from specs/SPEC.md:
//     BLOCKPOLICY_BENCH_ASSERT=1 go test ./blockpolicy -run=^$ -bench='BenchmarkEngineEvaluate_(100K|1M)$' -benchtime=3s
//     BLOCKPOLICY_BENCH_ASSERT=1 go test ./blockpolicy -run=^$ -bench='BenchmarkServeDNS_.*_(100K|1M)$' -benchtime=3s
//   - Run parser/matcher fuzzers:
//     GOCACHE=/tmp/go-build go test ./blockpolicy -run=^$ -fuzz=FuzzParseEntriesWithBlocky -fuzztime=30s
//     GOCACHE=/tmp/go-build go test ./blockpolicy -run=^$ -fuzz=FuzzEngineEvaluate -fuzztime=30s
