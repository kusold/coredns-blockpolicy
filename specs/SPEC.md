# CoreDNS Blockpolicy Plugin Spec (v0.1)

## 1. Purpose

Build a CoreDNS plugin that provides Blocky-like blocklist behavior inside CoreDNS, with policy selection driven by CoreDNS `view` server blocks.

The plugin is intentionally focused on blocklist features and does not attempt to replicate Blocky as a full DNS proxy.

## 2. Goals

1. Enforce domain blocking policies in CoreDNS with low query-path overhead.
2. Reuse Blocky-compatible list semantics (exact, wildcard, regex, hosts format).
3. Support Blocky-style deep checks in v1:
   1. CNAME chain blocking.
   2. Response-IP blocking.
4. Support list refresh by interval only (no manual trigger in v1).
5. Default block mode is `zeroip`.

## 3. Non-Goals (v1)

1. No client CIDR fallback inside plugin for policy selection.
2. No custom admin API/UI.
3. No query logging subsystem.
4. No upstream routing or resolver-group logic.
5. No distributed state sync.

## 4. Core Integration Model

Policy selection is handled by CoreDNS `view` by using separate server blocks, each with an instance of `blockpolicy` configured for that view's policy.

This avoids per-query client-group resolution overhead in the plugin and aligns with CoreDNS architecture.

## 5. Plugin Chain Placement

Recommended order in each server block:

1. `metadata` (if needed by other plugins).
2. `cache` (optional).
3. `blockpolicy` (must run before recursion/upstream forwarding).
4. `forward` / other resolver plugins.
5. `prometheus`.

`blockpolicy` should return early on block decisions and call `plugin.NextOrFailure` when query is allowed.

Rationale for `cache` before `blockpolicy` (speed-first default):

1. Cached responses are returned without invoking block matching logic on each query.
2. This reduces query-path CPU overhead, especially with regex/wildcard enabled.
3. It works with `view` because cache and policy stay scoped to each view/server block.

Tradeoff:

1. Cached allow responses may remain served until TTL expiry after a list/policy update.
2. Operators that prioritize immediate policy convergence can place `blockpolicy` before `cache`.

## 6. Supported Match Semantics (v1)

1. Exact domain match.
2. Wildcard domain match.
3. Regex match.
4. Hosts-format list parsing.
5. Allowlist precedence over denylist.
6. Deep CNAME check.
7. Response-IP list check.

Behavior choice for ambiguous list matching follows Blocky behavior where applicable: first found with warning logging.

## 7. DNS Response Modes

Supported:

1. `zeroip` (default):
   1. For `A`: answer `0.0.0.0`.
   2. For `AAAA`: answer `::`.
   3. For other QTYPEs: return `NXDOMAIN` (Blocky-compatible behavior target).
2. `nxdomain`.
3. `refused`.
4. `nodata`.
5. `sinkhole`:
   1. Custom IPv4/IPv6 addresses for `A`/`AAAA`.
   2. Non-`A/AAAA` falls back to `NXDOMAIN` unless explicitly configured otherwise in future versions.

TTL for synthetic answers is configurable (default: 60 seconds).

## 8. Configuration (Corefile-only, v1)

Configuration is per plugin instance (per server block/view). There is no `policy_by_view` directive in v1 because view-to-policy mapping is done by server-block layout.

### 8.1 Corefile Grammar (proposed)

```corefile
blockpolicy {
  # one policy per plugin instance in v1
  policy <name> {
    allow_groups <group> [<group>...]
    deny_groups  <group> [<group>...]
    block_mode   zeroip|nxdomain|refused|nodata|sinkhole
    sinkhole_ipv4 <ip>         # required when block_mode sinkhole and A is blocked
    sinkhole_ipv6 <ip>         # required when block_mode sinkhole and AAAA is blocked
    ttl <duration>             # default 60s
  }
  use_policy <name>

  list_group <name> {
    source <uri>               # repeatable; file:///... or http(s)://...
    format auto|hosts|domain|wildcard|regex
  }

  loading {
    refresh_period <duration>  # required; e.g. 4h
    startup_timeout <duration> # default 30s
    http_timeout <duration>    # default 10s
    max_body_size <bytes>      # default 20MB
  }

  matching {
    exact true|false           # default true
    wildcard true|false        # default true
    regex true|false           # default true
    hosts_format true|false    # default true
    deep_cname true|false      # default true
    response_ip_lists true|false # default true
  }

  logging {
    blocked true|false         # default true
    refresh_errors true|false  # default true
  }
}
```

### 8.2 Validation Rules

1. Exactly one `policy` must be selected via `use_policy`.
2. All referenced list groups in `allow_groups`/`deny_groups` must exist.
3. `refresh_period` must be >= 1 minute.
4. At least one deny list source must be present after initial load.
5. `sinkhole` mode requires at least one of `sinkhole_ipv4`/`sinkhole_ipv6`.
6. Unknown directives fail startup.
7. Invalid regex entries are counted and skipped unless configured as strict in future versions.

## 9. Data Model

1. `Snapshot` (immutable):
   1. Active policy.
   2. Compiled match trees/indexes.
   3. Compiled regex set.
   4. Response-IP structures.
   5. Metadata: build timestamp, source versions, counts.
2. `Engine`:
   1. Atomic pointer to `Snapshot`.
   2. Background refresher.
   3. Metrics collector.

The query path is read-only against the current snapshot.

## 10. Reload and Failure Behavior

1. Interval refresh only (`refresh_period`).
2. Last-good snapshot remains active if refresh fails.
3. Refresh failures increment metrics and log errors.
4. Startup behavior:
   1. Initial load must succeed within `startup_timeout`.
   2. If it fails, plugin startup fails and CoreDNS startup fails for that server block.

## 11. Query Processing Flow

1. Receive DNS request (`ServeDNS`).
2. Identify QNAME/QTYPE.
3. Allowlist lookup first.
4. Denylist lookup.
5. If deep CNAME is enabled and direct lookup not blocked, inspect CNAME chain response path where applicable.
6. If response-IP checking is enabled, inspect answer IPs against IP block structures.
7. If blocked, write synthetic response according to policy mode and return.
8. If allowed, continue to next plugin.

## 12. Observability

### 12.1 Metrics

1. `coredns_blockpolicy_queries_total{server,zone,view,policy,qtype}`
2. `coredns_blockpolicy_blocked_total{server,zone,view,policy,reason,mode,rcode}`
3. `coredns_blockpolicy_allowed_total{server,zone,view,policy}`
4. `coredns_blockpolicy_match_duration_seconds{phase}`
5. `coredns_blockpolicy_list_entries{policy,group,kind}`
6. `coredns_blockpolicy_refresh_total{policy,result}`
7. `coredns_blockpolicy_refresh_timestamp_seconds{policy}`
8. `coredns_blockpolicy_errors_total{stage,type}`

### 12.2 Logs

1. Primary query logging should use CoreDNS `log` plugin.
2. `blockpolicy` emits plugin-internal logs for refresh lifecycle and parse/load warnings.
3. Per-query block decision logging from `blockpolicy` is optional and disabled by default to avoid duplicate high-volume logs.
4. `blockpolicy` should publish metadata keys so `log` can include block context:
   1. `blockpolicy/policy`
   2. `blockpolicy/action` (`allow` or `block`)
   3. `blockpolicy/reason` (`denylist`, `allowlist`, `cname`, `response_ip`)
   4. `blockpolicy/mode` (`zeroip`, `nxdomain`, `refused`, `nodata`, `sinkhole`)
5. `dnstap` compatibility: blocked responses are written as normal DNS responses, so `dnstap` captures them without special integration.

## 13. Performance and Scale Targets

Target scale: comparable to Blocky-class usage.

v1 targets:

1. 1M+ domains loaded.
2. Query-path overhead p50 < 0.5 ms and p99 < 2 ms on commodity hardware, excluding network recursion time.
3. Refresh without blocking query path via atomic snapshot swap.
4. Memory growth is linear with entry count; no per-query allocations in steady state (goal).

## 14. Security and Safety

1. HTTP list downloads enforce timeout and max body size.
2. Optional allowlist of remote hostnames (future hardening).
3. Ignore malformed entries with counters; do not crash query path.
4. Synthetic answers are authoritative-only for generated response context and never cached internally by plugin state.

## 15. Iterative Delivery Plan

### Milestone 1: Skeleton + Exact Matching

1. Plugin registration, setup parsing, `ServeDNS` scaffolding.
2. One policy with exact domain deny/allow.
3. `zeroip` + `nxdomain` response modes.
4. Basic metrics.

### Milestone 2: List Loading + Refresh

1. File and HTTP(S) list loading.
2. Parser for `auto`/hosts/domain formats.
3. Interval refresh and last-good snapshot.
4. Startup timeout handling.

### Milestone 3: Wildcards + Regex

1. Wildcard matcher integration.
2. Regex matcher integration.
3. Parse error handling and metrics.

### Milestone 4: Deep Checks

1. CNAME chain checks.
2. Response-IP checks.
3. Consistency tests for Blocky-compatible semantics.

### Milestone 5: Hardening + Benchmarks

1. Benchmark at 100k, 1M entries.
2. p50/p99 overhead checks.
3. Fuzzing for list parsers and matchers.
4. Config validation and docs polish.

## 16. Testing Strategy

1. Unit tests:
   1. Parser correctness by format.
   2. Matching precedence.
   3. Response synthesis per QTYPE and mode.
2. Integration tests:
   1. CoreDNS plugin chain behavior.
   2. Interval refresh with successful and failed reloads.
3. Compatibility tests:
   1. Golden fixtures comparing expected Blocky-like behavior on selected rules.
4. Performance tests:
   1. Snapshot swap under load.
   2. Memory and latency at target scales.

## 17. Open Items

1. Confirm exact label source for `view` metric dimension (literal static label vs metadata-driven).
2. Decide strict vs permissive handling for invalid regex lists (v1 default: permissive with warnings).
3. Confirm whether `nodata` should return `NOERROR` empty with optional SOA authority in v1.

## 18. Future Integration: External Redis Sync Plugin (v2+)

Redis synchronization is out of scope for `blockpolicy` and should be implemented as a separate CoreDNS plugin.

`blockpolicy` integration requirements for that plugin:

1. `blockpolicy` remains the policy decision engine only.
2. Sync plugin is responsible for snapshot distribution and convergence across hosts.
3. Integration point is file/snapshot handoff, not direct Redis client logic inside `blockpolicy`.
4. `blockpolicy` continues interval refresh from local snapshot source; sync plugin updates that source.
5. On sync failure, `blockpolicy` keeps last-good in-memory snapshot.

Proposed contract between plugins:

1. Snapshot artifact format:
   1. `version` (monotonic).
   2. `created_at` timestamp.
   3. `checksum`.
   4. serialized lists/index inputs.
2. Delivery model:
   1. Sync plugin writes atomically to a watched local path (for example, temp file + rename).
   2. `blockpolicy` picks up on next interval refresh.
3. Safety model:
   1. `blockpolicy` validates checksum/version monotonicity before activation.
   2. Invalid or older snapshots are rejected with metrics and logs.
4. Operational model:
   1. Sync plugin may be disabled without changing `blockpolicy` behavior.
   2. Local file/http list loading remains valid fallback.

This keeps responsibilities separated and allows reuse of the same sync plugin for other consumers.

## 19. Example Corefile with Views

```corefile
# Kids view
.:53 {
  metadata
  view kids {
    expr incidr(client_ip(), '10.20.0.0/16')
  }

  blockpolicy {
    policy kids {
      allow_groups allow_internal
      deny_groups ads malware adult
      block_mode zeroip
      ttl 60s
    }
    use_policy kids

    list_group ads {
      source https://lists.example.net/ads.txt
      format auto
    }
    list_group malware {
      source https://lists.example.net/malware.txt
      format auto
    }
    list_group adult {
      source https://lists.example.net/adult.txt
      format auto
    }
    list_group allow_internal {
      source file:///etc/coredns/lists/allow-internal.txt
      format auto
    }

    loading {
      refresh_period 4h
      startup_timeout 30s
      http_timeout 10s
      max_body_size 20971520
    }

    matching {
      exact true
      wildcard true
      regex true
      hosts_format true
      deep_cname true
      response_ip_lists true
    }
  }

  cache 300
  forward . 1.1.1.1 9.9.9.9
  prometheus :9153
}

# Default view
.:53 {
  blockpolicy {
    policy default {
      deny_groups ads malware
      block_mode zeroip
      ttl 60s
    }
    use_policy default

    list_group ads {
      source https://lists.example.net/ads.txt
      format auto
    }
    list_group malware {
      source https://lists.example.net/malware.txt
      format auto
    }

    loading {
      refresh_period 4h
    }
  }

  cache 300
  forward . 1.1.1.1 9.9.9.9
  prometheus :9153
}
```
