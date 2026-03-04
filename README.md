# blockpolicy

## Name

*blockpolicy* - DNS blocklist enforcement with policy-driven blocking.

## Description

*blockpolicy* is a CoreDNS plugin that blocks DNS queries based on configurable deny and allow lists. It evaluates each incoming query against compiled domain lists and returns synthetic responses for blocked domains, passing allowed queries to the next plugin in the chain.

Key features:

- Exact, wildcard, and regex domain matching via [Blocky](https://github.com/0xERR0R/blocky) parser and trie components.
- Hosts-format list parsing.
- Allowlist precedence over denylist.
- Deep CNAME chain blocking.
- Response-IP blocking.
- Multiple block modes: `zeroip`, `nxdomain` (with `refused`, `nodata`, and `sinkhole` planned).
- Background list refresh with last-good snapshot on failure.
- Prometheus metrics for queries, blocks, allows, and refresh status.
- Metadata publishing for integration with the CoreDNS `log` plugin.
- Per-view policy selection using CoreDNS server blocks.

## Syntax

```
blockpolicy {
    policy <name> {
        allow_groups <group> [<group>...]
        deny_groups  <group> [<group>...]
        block_mode   zeroip|nxdomain
        ttl          <duration>
    }
    use_policy <name>

    list_group <name> {
        source <uri>
        format auto|hosts|domain|wildcard|regex
    }

    loading {
        refresh_period  <duration>
        startup_timeout <duration>
        http_timeout    <duration>
        max_body_size   <bytes>
    }

    matching {
        exact            true|false
        wildcard         true|false
        regex            true|false
        hosts_format     true|false
        deep_cname       true|false
        response_ip_lists true|false
    }

    fallthrough [ZONES...]
}
```

- **policy** defines a named blocking policy. Only one policy per plugin instance is supported.
  - **allow_groups** - list group names whose entries take precedence (allow over deny).
  - **deny_groups** - list group names whose entries are blocked. At least one is required.
  - **block_mode** - how blocked queries are answered. Default: `zeroip`.
    - `zeroip`: responds with `0.0.0.0` for A, `::` for AAAA, `NXDOMAIN` for other types.
    - `nxdomain`: responds with `NXDOMAIN` for all types.
  - **ttl** - TTL for synthetic blocked responses. Default: `60s`.
- **use_policy** selects which defined policy to activate.
- **list_group** defines a named group of blocklist sources. Repeatable for multiple groups.
  - **source** - URI of the list. Supports local file paths, `file:///...`, and `http(s)://...`. Repeatable within a group.
  - **format** - list format. Default: `auto`.
- **loading** configures list loading behavior.
  - **refresh_period** - how often lists are refreshed. Default: `4h`. Minimum: `1m`.
  - **startup_timeout** - maximum time to wait for the initial list load. Default: `30s`.
  - **http_timeout** - HTTP request timeout for remote lists. Default: `10s`.
  - **max_body_size** - maximum response body size for HTTP sources in bytes. Default: `20971520` (20 MB).
- **matching** enables or disables specific matching strategies. All default to `true`.
  - **exact** - exact domain matching.
  - **wildcard** - wildcard domain matching.
  - **regex** - regular expression matching.
  - **hosts_format** - parse hosts-format list entries.
  - **deep_cname** - inspect CNAME chain responses for blocked targets.
  - **response_ip_lists** - inspect answer IPs against IP deny lists.
- **fallthrough** - if a query matches a blocked domain but fallthrough is enabled (for the query's zone), pass the query to the next plugin instead of blocking. If no zones are specified, fallthrough applies to all zones.

## plugin.cfg Ordering

*blockpolicy* should run after `metadata` and `cache`, but before `forward` and other resolver plugins. Add this line to CoreDNS's `plugin.cfg` between `cache` and `rewrite`:

```
blockpolicy:github.com/kusold/coredns-blocklist/blockpolicy
```

Example ordering context:

```
metadata:metadata
cancel:cancel
tls:tls
reload:reload
...
cache:cache
blockpolicy:github.com/kusold/coredns-blocklist/blockpolicy
rewrite:rewrite
...
forward:forward
```

Placing `cache` before `blockpolicy` means cached responses are returned without invoking block matching on every query, reducing CPU overhead. The tradeoff is that cached allow responses may persist until TTL expiry after a list update. Operators who prioritize immediate policy convergence can place `blockpolicy` before `cache`.

## Examples

### Basic blocking

Block ads and malware domains using remote lists:

```corefile
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

    forward . 1.1.1.1 9.9.9.9
}
```

### With allowlist and local file

```corefile
.:53 {
    blockpolicy {
        policy default {
            allow_groups internal
            deny_groups ads
            block_mode nxdomain
        }
        use_policy default

        list_group ads {
            source https://lists.example.net/ads.txt
            format auto
        }
        list_group internal {
            source file:///etc/coredns/lists/allow.txt
            format domain
        }

        loading {
            refresh_period 4h
            startup_timeout 30s
            http_timeout 10s
        }
    }

    forward . 1.1.1.1
}
```

### Per-view policies with CoreDNS views

Use separate server blocks to apply different policies to different client groups:

```corefile
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
        }
    }

    cache 300
    forward . 1.1.1.1 9.9.9.9
}

.:53 {
    blockpolicy {
        policy default {
            deny_groups ads malware
            block_mode zeroip
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
}
```

### With fallthrough

Allow blocked queries to fall through to the next plugin instead of being blocked:

```corefile
.:53 {
    blockpolicy {
        policy default {
            deny_groups ads
            block_mode zeroip
        }
        use_policy default

        list_group ads {
            source https://lists.example.net/ads.txt
            format auto
        }

        loading {
            refresh_period 4h
        }

        fallthrough
    }

    forward . 1.1.1.1
}
```

## Metadata

*blockpolicy* publishes the following metadata keys, usable by the CoreDNS `log` plugin and other metadata consumers:

| Key | Description | Example values |
|-----|-------------|----------------|
| `blockpolicy/policy` | Active policy name | `default`, `kids` |
| `blockpolicy/action` | Decision taken | `allow`, `block` |
| `blockpolicy/reason` | Why the decision was made | `denylist`, `allowlist`, `cname`, `response_ip`, `passthrough`, `empty_question` |
| `blockpolicy/mode` | Block mode used (only for block actions) | `zeroip`, `nxdomain` |

## Metrics

If monitoring is enabled (via the `prometheus` plugin), the following metrics are exported:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `coredns_blockpolicy_queries_total` | counter | server, zone, view, policy, qtype | Total DNS queries evaluated |
| `coredns_blockpolicy_blocked_total` | counter | server, zone, view, policy, reason, mode, rcode | Blocked queries |
| `coredns_blockpolicy_allowed_total` | counter | server, zone, view, policy, reason | Allowed queries |
| `coredns_blockpolicy_match_duration_seconds` | histogram | phase | Time spent in matching phases |
| `coredns_blockpolicy_list_entries` | gauge | policy, group, kind | Number of loaded list entries |
| `coredns_blockpolicy_refresh_total` | counter | policy, result | List refresh attempts by result |
| `coredns_blockpolicy_refresh_timestamp_seconds` | gauge | policy | Unix timestamp of last successful refresh |
| `coredns_blockpolicy_errors_total` | counter | stage, type | Plugin errors by stage and type |

## Health and Ready

*blockpolicy* supports both the CoreDNS `ready` and `health` plugins:

- **Ready**: reports ready once the initial list snapshot is loaded.
- **Health**: reports unhealthy after 3 consecutive list refresh failures. The last-good snapshot continues serving queries during this state.

## Building

*blockpolicy* is an external CoreDNS plugin. To build CoreDNS with this plugin, add the `plugin.cfg` entry described above and rebuild:

```sh
git clone https://github.com/coredns/coredns
cd coredns
# Add the blockpolicy line to plugin.cfg (see plugin.cfg Ordering above)
go generate
go build
```
