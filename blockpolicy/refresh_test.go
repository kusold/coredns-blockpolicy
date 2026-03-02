package blockpolicy

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
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
}
