//go:build coredns

package blockpolicy

import (
	"fmt"
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
	cfg := &Config{
		ListGroups: map[string]ListGroupConfig{},
	}

	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "policy":
				nameAndMode, err := parsePolicy(c)
				if err != nil {
					return nil, err
				}
				cfg.PolicyName = nameAndMode.name
				cfg.Policy = nameAndMode.policy
			case "use_policy":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				if cfg.PolicyName != "" && cfg.PolicyName != args[0] {
					return nil, fmt.Errorf("use_policy %q does not match configured policy %q", args[0], cfg.PolicyName)
				}
				cfg.PolicyName = args[0]
			case "list_group":
				name, group, err := parseListGroup(c)
				if err != nil {
					return nil, err
				}
				cfg.ListGroups[name] = group
			case "loading":
				if err := parseLoading(c); err != nil {
					return nil, err
				}
			case "matching":
				if err := skipBlock(c); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("unknown directive %q", c.Val())
			}
		}
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

type namedPolicy struct {
	name   string
	policy PolicyConfig
}

func parsePolicy(c *caddy.Controller) (namedPolicy, error) {
	args := c.RemainingArgs()
	if len(args) != 1 {
		return namedPolicy{}, c.ArgErr()
	}
	p := PolicyConfig{
		Mode: modeZeroIP,
		TTL:  60 * time.Second,
	}

	for c.NextBlock() {
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
			p.Mode = blockMode(vals[0])
		case "ttl":
			vals := c.RemainingArgs()
			if len(vals) != 1 {
				return namedPolicy{}, c.ArgErr()
			}
			ttl, err := time.ParseDuration(vals[0])
			if err != nil {
				return namedPolicy{}, fmt.Errorf("invalid ttl %q: %w", vals[0], err)
			}
			p.TTL = ttl
		default:
			return namedPolicy{}, fmt.Errorf("unknown policy directive %q", c.Val())
		}
	}

	if len(p.DenyGroups) == 0 {
		return namedPolicy{}, fmt.Errorf("policy %q requires at least one deny_groups entry", args[0])
	}

	return namedPolicy{name: args[0], policy: p}, nil
}

func parseListGroup(c *caddy.Controller) (string, ListGroupConfig, error) {
	args := c.RemainingArgs()
	if len(args) != 1 {
		return "", ListGroupConfig{}, c.ArgErr()
	}
	group := ListGroupConfig{Format: "auto"}
	for c.NextBlock() {
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
	if len(group.Sources) == 0 {
		return "", ListGroupConfig{}, fmt.Errorf("list_group %q requires at least one source", args[0])
	}
	return args[0], group, nil
}

func parseLoading(c *caddy.Controller) error {
	for c.NextBlock() {
		switch c.Val() {
		case "refresh_period", "startup_timeout", "http_timeout", "max_body_size":
			if len(c.RemainingArgs()) != 1 {
				return c.ArgErr()
			}
		default:
			return fmt.Errorf("unknown loading directive %q", c.Val())
		}
	}
	return nil
}

func skipBlock(c *caddy.Controller) error {
	for c.NextBlock() {
		if len(c.RemainingArgs()) != 1 {
			return c.ArgErr()
		}
	}
	return nil
}
