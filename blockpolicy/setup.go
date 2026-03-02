//go:build coredns

package blockpolicy

import (
	"fmt"
	"strconv"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() {
	plugin.Register("blockpolicy", setup)
}

func setup(c *caddy.Controller) error {
	cfg, err := parseConfig(c)
	if err != nil {
		return plugin.Error("blockpolicy", err)
	}
	allow, deny, err := loadExactDomains(cfg)
	if err != nil {
		return plugin.Error("blockpolicy", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return New(next, cfg, allow, deny)
	})
	return nil
}

func parseConfig(c *caddy.Controller) (*Config, error) {
	cfg := &Config{ListGroups: map[string]ListGroupConfig{}}

	for c.Next() {
		if c.Val() != "blockpolicy" {
			continue
		}
		if !c.NextArg() {
			return nil, c.ArgErr()
		}
		if c.Val() != "{" {
			return nil, c.SyntaxErr("{")
		}
		if err := parseTopLevelBlock(c, cfg); err != nil {
			return nil, err
		}
	}

	if err := cfg.applyDefaultsAndValidate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func parseTopLevelBlock(c *caddy.Controller, cfg *Config) error {
	for c.Next() {
		switch c.Val() {
		case "}":
			return nil
		case "policy":
			nameAndPolicy, err := parsePolicy(c)
			if err != nil {
				return err
			}
			cfg.PolicyName = nameAndPolicy.name
			cfg.Policy = nameAndPolicy.policy
		case "use_policy":
			args := c.RemainingArgs()
			if len(args) != 1 {
				return c.ArgErr()
			}
			if cfg.PolicyName != "" && cfg.PolicyName != args[0] {
				return fmt.Errorf("use_policy %q does not match configured policy %q", args[0], cfg.PolicyName)
			}
			cfg.PolicyName = args[0]
		case "list_group":
			name, group, err := parseListGroup(c)
			if err != nil {
				return err
			}
			cfg.ListGroups[name] = group
		case "loading":
			loading, err := parseLoading(c)
			if err != nil {
				return err
			}
			cfg.Loading = loading
		case "matching":
			matching, err := parseMatching(c)
			if err != nil {
				return err
			}
			cfg.Matching = matching
		case "logging":
			return fmt.Errorf("logging block not yet supported")
		default:
			return fmt.Errorf("unknown directive %q", c.Val())
		}
	}
	return c.EOFErr()
}

type namedPolicy struct {
	name   string
	policy PolicyConfig
}

func parsePolicy(c *caddy.Controller) (namedPolicy, error) {
	if !c.NextArg() {
		return namedPolicy{}, c.ArgErr()
	}
	name := c.Val()
	if !c.NextArg() {
		return namedPolicy{}, c.ArgErr()
	}
	if c.Val() != "{" {
		return namedPolicy{}, c.SyntaxErr("{")
	}

	p := PolicyConfig{Mode: modeZeroIP, TTL: 60 * time.Second}
	for c.Next() {
		if c.Val() == "}" {
			if len(p.DenyGroups) == 0 {
				return namedPolicy{}, fmt.Errorf("policy %q requires at least one deny_groups entry", name)
			}
			return namedPolicy{name: name, policy: p}, nil
		}
		switch c.Val() {
		case "allow_groups":
			p.AllowGroups = append(p.AllowGroups, c.RemainingArgs()...)
		case "deny_groups":
			p.DenyGroups = append(p.DenyGroups, c.RemainingArgs()...)
		case "block_mode":
			vals := c.RemainingArgs()
			if len(vals) != 1 {
				return namedPolicy{}, c.ArgErr()
			}
			mode := blockMode(vals[0])
			switch mode {
			case modeZeroIP, modeNXDomain:
				p.Mode = mode
			default:
				return namedPolicy{}, fmt.Errorf("unsupported block_mode %q", vals[0])
			}
		case "ttl":
			ttl, err := parseDurationDirective(c, "ttl")
			if err != nil {
				return namedPolicy{}, err
			}
			p.TTL = ttl
		default:
			return namedPolicy{}, fmt.Errorf("unknown policy directive %q", c.Val())
		}
	}
	return namedPolicy{}, c.EOFErr()
}

func parseListGroup(c *caddy.Controller) (string, ListGroupConfig, error) {
	if !c.NextArg() {
		return "", ListGroupConfig{}, c.ArgErr()
	}
	name := c.Val()
	if !c.NextArg() {
		return "", ListGroupConfig{}, c.ArgErr()
	}
	if c.Val() != "{" {
		return "", ListGroupConfig{}, c.SyntaxErr("{")
	}

	group := ListGroupConfig{Format: "auto"}
	for c.Next() {
		if c.Val() == "}" {
			if len(group.Sources) == 0 {
				return "", ListGroupConfig{}, fmt.Errorf("list_group %q requires at least one source", name)
			}
			return name, group, nil
		}
		switch c.Val() {
		case "source":
			vals := c.RemainingArgs()
			if len(vals) != 1 {
				return "", ListGroupConfig{}, c.ArgErr()
			}
			group.Sources = append(group.Sources, vals[0])
		case "format":
			vals := c.RemainingArgs()
			if len(vals) != 1 {
				return "", ListGroupConfig{}, c.ArgErr()
			}
			group.Format = vals[0]
		default:
			return "", ListGroupConfig{}, fmt.Errorf("unknown list_group directive %q", c.Val())
		}
	}
	return "", ListGroupConfig{}, c.EOFErr()
}

func parseLoading(c *caddy.Controller) (LoadingConfig, error) {
	if !c.NextArg() {
		return LoadingConfig{}, c.ArgErr()
	}
	if c.Val() != "{" {
		return LoadingConfig{}, c.SyntaxErr("{")
	}

	cfg := LoadingConfig{}
	for c.Next() {
		if c.Val() == "}" {
			return cfg, nil
		}
		switch c.Val() {
		case "refresh_period":
			d, err := parseDurationDirective(c, "refresh_period")
			if err != nil {
				return LoadingConfig{}, err
			}
			cfg.RefreshPeriod = d
		case "startup_timeout":
			d, err := parseDurationDirective(c, "startup_timeout")
			if err != nil {
				return LoadingConfig{}, err
			}
			cfg.StartupTimeout = d
		case "http_timeout":
			d, err := parseDurationDirective(c, "http_timeout")
			if err != nil {
				return LoadingConfig{}, err
			}
			cfg.HTTPTimeout = d
		case "max_body_size":
			args := c.RemainingArgs()
			if len(args) != 1 {
				return LoadingConfig{}, c.ArgErr()
			}
			sz, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return LoadingConfig{}, fmt.Errorf("invalid max_body_size %q: %w", args[0], err)
			}
			cfg.MaxBodySize = sz
		default:
			return LoadingConfig{}, fmt.Errorf("unknown loading directive %q", c.Val())
		}
	}
	return LoadingConfig{}, c.EOFErr()
}

func parseMatching(c *caddy.Controller) (MatchingConfig, error) {
	if !c.NextArg() {
		return MatchingConfig{}, c.ArgErr()
	}
	if c.Val() != "{" {
		return MatchingConfig{}, c.SyntaxErr("{")
	}

	cfg := MatchingConfig{}
	for c.Next() {
		if c.Val() == "}" {
			return cfg, nil
		}
		switch c.Val() {
		case "exact":
			v, err := parseBoolDirective(c, "exact")
			if err != nil {
				return MatchingConfig{}, err
			}
			cfg.Exact = v
		case "wildcard":
			v, err := parseBoolDirective(c, "wildcard")
			if err != nil {
				return MatchingConfig{}, err
			}
			cfg.Wildcard = v
		case "regex":
			v, err := parseBoolDirective(c, "regex")
			if err != nil {
				return MatchingConfig{}, err
			}
			cfg.Regex = v
		case "hosts_format":
			v, err := parseBoolDirective(c, "hosts_format")
			if err != nil {
				return MatchingConfig{}, err
			}
			cfg.HostsFormat = v
		case "deep_cname":
			v, err := parseBoolDirective(c, "deep_cname")
			if err != nil {
				return MatchingConfig{}, err
			}
			cfg.DeepCNAME = v
		case "response_ip_lists":
			v, err := parseBoolDirective(c, "response_ip_lists")
			if err != nil {
				return MatchingConfig{}, err
			}
			cfg.ResponseIPLists = v
		default:
			return MatchingConfig{}, fmt.Errorf("unknown matching directive %q", c.Val())
		}
	}
	return MatchingConfig{}, c.EOFErr()
}

func parseBoolDirective(c *caddy.Controller, directive string) (bool, error) {
	args := c.RemainingArgs()
	if len(args) != 1 {
		return false, c.ArgErr()
	}
	v, err := strconv.ParseBool(args[0])
	if err != nil {
		return false, fmt.Errorf("invalid bool value for %q: %w", directive, err)
	}
	return v, nil
}

func parseDurationDirective(c *caddy.Controller, directive string) (time.Duration, error) {
	args := c.RemainingArgs()
	if len(args) != 1 {
		return 0, c.ArgErr()
	}
	d, err := time.ParseDuration(args[0])
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", directive, args[0], err)
	}
	return d, nil
}
