package blockpolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBlockPolicyLifecycleStartStopIdempotent(t *testing.T) {
	tmp := t.TempDir()
	denyFile := filepath.Join(tmp, "deny.txt")
	if err := os.WriteFile(denyFile, []byte("deny.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	policy := fmt.Sprintf("lifecycle-%d", time.Now().UnixNano())
	cfg := &Config{
		PolicyName: policy,
		Policy: PolicyConfig{
			Mode:       modeZeroIP,
			DenyGroups: []string{"deny"},
		},
		ListGroups: map[string]ListGroupConfig{
			"deny": {Sources: []string{denyFile}, Format: "domain"},
		},
		Loading: LoadingConfig{
			RefreshPeriod: 25 * time.Millisecond,
		},
	}

	bp := NewWithMatchers(&noopNext{}, cfg, matcherSet{}, matcherSet{exact: map[string]struct{}{"old.example": {}}})
	if !bp.Ready() {
		t.Fatalf("expected blockpolicy to report ready with initial engine")
	}

	if err := bp.OnStartup(); err != nil {
		t.Fatalf("OnStartup failed: %v", err)
	}
	if err := bp.OnStartup(); err != nil {
		t.Fatalf("second OnStartup failed: %v", err)
	}

	waitForCondition(t, time.Second, 10*time.Millisecond, func() bool {
		return metricCounterValue(t, refreshTotal.WithLabelValues(policy, "success")) >= 1
	})

	if err := bp.OnShutdown(); err != nil {
		t.Fatalf("OnShutdown failed: %v", err)
	}
	if err := bp.OnShutdown(); err != nil {
		t.Fatalf("second OnShutdown failed: %v", err)
	}

	select {
	case <-bp.doneCh:
	default:
		t.Fatalf("expected refresh loop done channel to be closed")
	}

	successBefore := metricCounterValue(t, refreshTotal.WithLabelValues(policy, "success"))
	time.Sleep(80 * time.Millisecond)
	successAfter := metricCounterValue(t, refreshTotal.WithLabelValues(policy, "success"))
	if successAfter != successBefore {
		t.Fatalf("expected no refreshes after shutdown, before=%v after=%v", successBefore, successAfter)
	}
}

func TestBlockPolicyOnShutdownWithoutStartup(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		PolicyName: "no-startup",
		Policy: PolicyConfig{
			Mode: modeZeroIP,
		},
	}
	bp := NewWithMatchers(&noopNext{}, cfg, matcherSet{}, matcherSet{})
	if err := bp.OnShutdown(); err != nil {
		t.Fatalf("OnShutdown without startup failed: %v", err)
	}
}

func waitForCondition(t *testing.T, timeout, step time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(step)
	}
	t.Fatalf("condition not met within %s", timeout)
}
