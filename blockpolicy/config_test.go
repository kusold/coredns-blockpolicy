package blockpolicy

import (
	"testing"
	"time"
)

func TestConfigValidateRequiresUsePolicy(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Policy: PolicyConfig{
			DenyGroups: []string{"ads"},
		},
		ListGroups: map[string]ListGroupConfig{
			"ads": {Sources: []string{"/tmp/ads.txt"}},
		},
	}
	if err := cfg.applyDefaultsAndValidate(); err == nil {
		t.Fatalf("expected validation failure when use_policy is missing")
	}
}

func TestConfigValidateRejectsUnknownGroup(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		PolicyName: "default",
		Policy: PolicyConfig{
			DenyGroups: []string{"missing"},
		},
		ListGroups: map[string]ListGroupConfig{},
	}
	if err := cfg.applyDefaultsAndValidate(); err == nil {
		t.Fatalf("expected validation failure for missing deny group")
	}
}

func TestConfigValidateSetsDefaults(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		PolicyName: "default",
		Policy: PolicyConfig{
			DenyGroups: []string{"ads"},
		},
		ListGroups: map[string]ListGroupConfig{
			"ads": {Sources: []string{"/tmp/ads.txt"}},
		},
	}
	if err := cfg.applyDefaultsAndValidate(); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
	if cfg.Policy.Mode != modeZeroIP {
		t.Fatalf("expected default mode zeroip, got %q", cfg.Policy.Mode)
	}
	if cfg.Policy.TTL != 60*time.Second {
		t.Fatalf("expected default ttl 60s, got %s", cfg.Policy.TTL)
	}
	if cfg.Loading.RefreshPeriod != 4*time.Hour {
		t.Fatalf("expected refresh default 4h, got %s", cfg.Loading.RefreshPeriod)
	}
}

func TestConfigValidateRejectsUnsupportedMode(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		PolicyName: "default",
		Policy: PolicyConfig{
			DenyGroups: []string{"ads"},
			Mode:       "refused",
		},
		ListGroups: map[string]ListGroupConfig{
			"ads": {Sources: []string{"/tmp/ads.txt"}},
		},
	}
	if err := cfg.applyDefaultsAndValidate(); err == nil {
		t.Fatalf("expected unsupported mode to fail validation")
	}
}

func TestConfigValidateRejectsNegativeTTL(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		PolicyName: "default",
		Policy: PolicyConfig{
			DenyGroups: []string{"ads"},
			TTL:        -1 * time.Second,
		},
		ListGroups: map[string]ListGroupConfig{
			"ads": {Sources: []string{"/tmp/ads.txt"}},
		},
	}
	if err := cfg.applyDefaultsAndValidate(); err == nil {
		t.Fatalf("expected negative ttl to fail validation")
	}
}

func TestNormalizeNames(t *testing.T) {
	t.Parallel()
	if got := normalizeQueryName("  ExAmPlE.COM. "); got != "example.com" {
		t.Fatalf("unexpected normalized query name: %q", got)
	}
	if got := normalizeExactListEntry("*.example.com."); got != "*.example.com" {
		t.Fatalf("unexpected normalized list entry: %q", got)
	}
}
