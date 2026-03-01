package blockpolicy

// Package blockpolicy contains two layers:
// - Core policy engine and list parsing (no CoreDNS dependencies).
// - CoreDNS adapter files behind the `coredns` build tag.
//
// This split keeps core matching logic testable in constrained environments while
// preserving full CoreDNS integration when built with `-tags coredns`.
