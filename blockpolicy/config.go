package blockpolicy

import (
	"fmt"
	"strings"
	"time"
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

	if c.Policy.Mode == "" {
		c.Policy.Mode = modeZeroIP
	}
	if c.Policy.Mode != modeZeroIP && c.Policy.Mode != modeNXDomain {
		return fmt.Errorf("unsupported block_mode %q in milestone 1", c.Policy.Mode)
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
	if c.Loading.StartupTimeout == 0 {
		c.Loading.StartupTimeout = 30 * time.Second
	}
	if c.Loading.HTTPTimeout == 0 {
		c.Loading.HTTPTimeout = 10 * time.Second
	}
	if c.Loading.MaxBodySize == 0 {
		c.Loading.MaxBodySize = 20 * 1024 * 1024
	}

	if !c.Matching.Exact && !c.Matching.Wildcard && !c.Matching.Regex && !c.Matching.HostsFormat {
		// Milestone 1 only supports exact matching. Keep others parsed for forward compatibility.
		c.Matching.Exact = true
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
