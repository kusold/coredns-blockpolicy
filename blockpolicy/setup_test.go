//go:build coredns

package blockpolicy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/coredns/caddy"
)

func TestParseConfig(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	denyFile := filepath.Join(tmp, "deny.txt")
	if err := os.WriteFile(denyFile, []byte("ads.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	corefile := `blockpolicy {
		policy default {
			deny_groups ads
			block_mode zeroip
			ttl 30s
		}
		use_policy default
		list_group ads {
			source ` + denyFile + `
			format auto
		}
		loading {
			refresh_period 4h
		}
	}`

	c := caddy.NewTestController("dns", corefile)

	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig failed: %v", err)
	}
	if cfg.PolicyName != "default" {
		t.Fatalf("expected default policy, got %q", cfg.PolicyName)
	}
	if cfg.Policy.Mode != modeZeroIP {
		t.Fatalf("expected zeroip mode")
	}
}

func TestParseConfigUsePolicyMismatch(t *testing.T) {
	t.Parallel()
	corefile := `blockpolicy {
		policy default {
			deny_groups ads
		}
		use_policy other
		list_group ads {
			source /tmp/ads.txt
		}
	}`

	c := caddy.NewTestController("dns", corefile)

	if _, err := parseConfig(c); err == nil {
		t.Fatalf("expected parseConfig to fail on use_policy mismatch")
	}
}
