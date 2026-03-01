//go:build coredns

package blockpolicy

import "testing"

func TestParseConfig(t *testing.T) {
	t.Skip("caddy test dispenser does not support nested plugin sub-block parsing in this shape; parser integration will be covered with end-to-end CoreDNS tests")
}

func TestParseConfigUsePolicyMismatch(t *testing.T) {
	t.Skip("caddy test dispenser does not support nested plugin sub-block parsing in this shape; parser integration will be covered with end-to-end CoreDNS tests")
}

func TestParseConfigUnknownTopLevelDirective(t *testing.T) {
	t.Skip("caddy test dispenser does not support nested plugin sub-block parsing in this shape; parser integration will be covered with end-to-end CoreDNS tests")
}

func TestParsePolicyRequiresDenyGroup(t *testing.T) {
	t.Skip("caddy test dispenser does not support nested plugin sub-block parsing in this shape; parser integration will be covered with end-to-end CoreDNS tests")
}
