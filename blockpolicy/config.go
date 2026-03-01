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

func (c *Config) validate() error {
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

func normalizeName(name string) string {
	trimmed := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	return strings.TrimPrefix(trimmed, "*.")
}
