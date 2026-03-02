package blockpolicy

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
)

func TestRefreshOnceSwapsSnapshotAndKeepsLastGoodOnFailure(t *testing.T) {
	t.Parallel()

	var failRefresh atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failRefresh.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("new.example\n"))
	}))
	defer srv.Close()

	cfg := &Config{
		PolicyName: "default",
		Policy: PolicyConfig{
			Mode:       modeZeroIP,
			DenyGroups: []string{"deny"},
		},
		ListGroups: map[string]ListGroupConfig{
			"deny": {
				Sources: []string{srv.URL},
				Format:  "auto",
			},
		},
		Loading: LoadingConfig{
			RefreshPeriod: time.Hour,
			HTTPTimeout:   time.Second,
			MaxBodySize:   1024,
		},
	}

	bp := New(&noopNext{}, cfg, nil, map[string]struct{}{"old.example": {}})

	bp.refreshOnce()
	if got := bp.currentEngine().Evaluate("new.example.", queryTypeA); got.Action != actionBlock {
		t.Fatalf("expected new.example to be blocked after successful refresh")
	}
	if got := bp.currentEngine().Evaluate("old.example.", queryTypeA); got.Action != actionAllow {
		t.Fatalf("expected old.example to no longer be blocked after successful refresh")
	}

	failRefresh.Store(true)
	bp.refreshOnce()
	if got := bp.currentEngine().Evaluate("new.example.", queryTypeA); got.Action != actionBlock {
		t.Fatalf("expected last-good snapshot to remain active after failed refresh")
	}

	if got := metricCounterValue(t, refreshTotal.WithLabelValues("default", "success")); got < 1 {
		t.Fatalf("expected successful refresh counter to increment, got %v", got)
	}
	if got := metricCounterValue(t, refreshTotal.WithLabelValues("default", "error")); got < 1 {
		t.Fatalf("expected failed refresh counter to increment, got %v", got)
	}
	if got := metricCounterValue(t, errorsTotal.WithLabelValues("refresh", "load")); got < 1 {
		t.Fatalf("expected refresh load errors counter to increment, got %v", got)
	}
	if got := metricGaugeValue(t, refreshTimestamp.WithLabelValues("default")); got <= 0 {
		t.Fatalf("expected refresh timestamp to be set, got %v", got)
	}
}

func metricCounterValue(t *testing.T, c interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := c.Write(m); err != nil {
		t.Fatalf("failed to read metric: %v", err)
	}
	if m.Counter == nil || m.Counter.Value == nil {
		t.Fatalf("counter metric was not set")
	}
	return *m.Counter.Value
}
