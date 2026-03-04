package blockpolicy

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin/pkg/fall"
)

type blockMode string

const (
	modeZeroIP   blockMode = "zeroip"
	modeNXDomain blockMode = "nxdomain"
)

type Config struct {
	PolicyName string
	Policy     PolicyConfig
	ListGroups map[string]ListGroupConfig
	Loading    LoadingConfig
	Matching   MatchingConfig
	Fall       fall.F

	// matchingConfigured tracks whether a matching block was explicitly set in
	// Corefile parsing so zero-values can be distinguished from defaults.
	matchingConfigured bool
}

type PolicyConfig struct {
	AllowGroups []string
	DenyGroups  []string
	Mode        blockMode
	TTL         time.Duration
}

type ListGroupConfig struct {
	Sources []string
	Format  string
}

type LoadingConfig struct {
	RefreshPeriod  time.Duration
	StartupTimeout time.Duration
	HTTPTimeout    time.Duration
	MaxBodySize    int64
}

type MatchingConfig struct {
	Exact           bool
	Wildcard        bool
	Regex           bool
	HostsFormat     bool
	DeepCNAME       bool
	ResponseIPLists bool
}

func (c *Config) applyDefaultsAndValidate() error {
	if c.PolicyName == "" {
		return fmt.Errorf("use_policy is required")
	}
	// Keep this check for defense-in-depth: applyDefaultsAndValidate can be
	// called on programmatically-constructed Config values, not only Corefile parsing.
	if len(c.Policy.DenyGroups) == 0 {
		return fmt.Errorf("policy %q requires at least one deny_groups entry", c.PolicyName)
	}

	if c.Policy.Mode == "" {
		c.Policy.Mode = modeZeroIP
	}
	if c.Policy.Mode != modeZeroIP && c.Policy.Mode != modeNXDomain {
		return fmt.Errorf("unsupported block_mode %q", c.Policy.Mode)
	}

	if c.Policy.TTL == 0 {
		c.Policy.TTL = 60 * time.Second
	}
	if c.Policy.TTL < 0 {
		return fmt.Errorf("ttl must be >= 0")
	}

	if c.Loading.RefreshPeriod == 0 {
		c.Loading.RefreshPeriod = 4 * time.Hour
	}
	if c.Loading.RefreshPeriod < time.Minute {
		return fmt.Errorf("refresh_period must be >= 1m")
	}
	if c.Loading.StartupTimeout == 0 {
		c.Loading.StartupTimeout = 30 * time.Second
	}
	if c.Loading.StartupTimeout < 0 {
		return fmt.Errorf("startup_timeout must be >= 0")
	}
	if c.Loading.HTTPTimeout == 0 {
		c.Loading.HTTPTimeout = 10 * time.Second
	}
	if c.Loading.HTTPTimeout < 0 {
		return fmt.Errorf("http_timeout must be >= 0")
	}
	if c.Loading.MaxBodySize == 0 {
		c.Loading.MaxBodySize = 20 * 1024 * 1024
	}
	if c.Loading.MaxBodySize < 0 {
		return fmt.Errorf("max_body_size must be >= 0")
	}

	if !c.matchingConfigured {
		c.Matching = effectiveMatchingConfig(c.Matching)
	}

	for name, group := range c.ListGroups {
		if len(group.Sources) == 0 {
			return fmt.Errorf("list_group %q requires at least one source", name)
		}
		normalizedSources := make([]string, 0, len(group.Sources))
		for _, source := range group.Sources {
			normalized, err := normalizeAndValidateSource(source)
			if err != nil {
				return fmt.Errorf("invalid source in list_group %q: %w", name, err)
			}
			normalizedSources = append(normalizedSources, normalized)
		}
		group.Sources = normalizedSources
		group.Format = strings.ToLower(strings.TrimSpace(group.Format))
		if group.Format == "" {
			group.Format = "auto"
		}
		if !isSupportedListFormat(group.Format) {
			return fmt.Errorf("unsupported list_group %q format %q (not yet supported)", name, group.Format)
		}
		c.ListGroups[name] = group
	}

	for _, g := range c.Policy.AllowGroups {
		if _, ok := c.ListGroups[g]; !ok {
			return fmt.Errorf("allow group %q does not exist", g)
		}
	}
	for _, g := range c.Policy.DenyGroups {
		if _, ok := c.ListGroups[g]; !ok {
			return fmt.Errorf("deny group %q does not exist", g)
		}
	}
	return nil
}

func normalizeQueryName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func normalizeExactListEntry(name string) string {
	return normalizeQueryName(name)
}

func effectiveMatchingConfig(cfg MatchingConfig) MatchingConfig {
	if cfg != (MatchingConfig{}) {
		return cfg
	}
	return MatchingConfig{
		Exact:           true,
		Wildcard:        true,
		Regex:           true,
		HostsFormat:     true,
		DeepCNAME:       true,
		ResponseIPLists: true,
	}
}

func isSupportedListFormat(format string) bool {
	switch format {
	case "auto", "hosts", "domain", "wildcard", "regex":
		return true
	default:
		return false
	}
}

func normalizeAndValidateSource(source string) (string, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return "", fmt.Errorf("source must not be empty")
	}
	if !strings.Contains(source, "://") {
		return source, nil
	}

	u, err := url.Parse(source)
	if err != nil {
		return "", fmt.Errorf("parse source %q: %w", source, err)
	}
	switch u.Scheme {
	case "http", "https":
		if u.Host == "" {
			return "", fmt.Errorf("source %q must include host", source)
		}
	case "file":
		if u.Path == "" {
			return "", fmt.Errorf("source %q must include path", source)
		}
	default:
		return "", fmt.Errorf("unsupported source scheme %q", u.Scheme)
	}
	return source, nil
}
