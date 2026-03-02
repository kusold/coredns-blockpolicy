package blockpolicy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
)

func TestParseDomainsWithBlockyAutoParsesDomainAndHosts(t *testing.T) {
	t.Parallel()
	content := `# comment
ads.example
0.0.0.0 tracking.example
:: another.example
ads2.example # inline
0.0.0.0 tracking2.example # inline
`

	got := map[string]struct{}{}
	if err := parseDomainsWithBlocky(context.Background(), "auto", "inline", strings.NewReader(content), got); err != nil {
		t.Fatalf("parseDomainsWithBlocky failed: %v", err)
	}

	for _, want := range []string{"ads.example", "tracking.example", "another.example", "ads2.example", "tracking2.example"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("expected %q in set", want)
		}
	}
}

func TestSourcePath(t *testing.T) {
	t.Parallel()
	path, err := sourcePath("file:///tmp/test.txt")
	if err != nil {
		t.Fatalf("sourcePath returned error: %v", err)
	}
	if path != "/tmp/test.txt" {
		t.Fatalf("unexpected file path: %q", path)
	}

	if _, err := sourcePath("https://example.com/list.txt"); err == nil {
		t.Fatalf("expected http source to not be treated as local path")
	}
}

func TestParseDomainsWithBlockyHostsOnly(t *testing.T) {
	t.Parallel()

	content := `ads.example
0.0.0.0 tracking.example
127.0.0.1 another.example alias.example
`
	got := map[string]struct{}{}
	if err := parseDomainsWithBlocky(context.Background(), "hosts", "inline", strings.NewReader(content), got); err != nil {
		t.Fatalf("parseDomainsWithBlocky failed: %v", err)
	}

	for _, want := range []string{"tracking.example", "another.example", "alias.example"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("expected %q in set", want)
		}
	}
	if _, ok := got["ads.example"]; ok {
		t.Fatalf("did not expect non-hosts line to be parsed in hosts format")
	}
}

func TestParseDomainsWithBlockyDomain(t *testing.T) {
	t.Parallel()

	content := "alpha.example\nbeta.example\n"
	got := map[string]struct{}{}
	if err := parseDomainsWithBlocky(context.Background(), "domain", "inline", strings.NewReader(content), got); err != nil {
		t.Fatalf("parseDomainsWithBlocky failed: %v", err)
	}
	for _, want := range []string{"alpha.example", "beta.example"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("expected %q in set", want)
		}
	}
}

func TestParseDomainsWithBlockyRespectsContextCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got := map[string]struct{}{}
	err := parseDomainsWithBlocky(ctx, "auto", "inline", strings.NewReader("alpha.example\n"), got)
	if err == nil {
		t.Fatalf("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestLoadExactDomainsWithContext(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()

	allowFile := filepath.Join(tmp, "allow.txt")
	if err := os.WriteFile(allowFile, []byte("allow.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	denyFile := filepath.Join(tmp, "deny.txt")
	if err := os.WriteFile(denyFile, []byte("deny.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		PolicyName: "default",
		Policy: PolicyConfig{
			AllowGroups: []string{"allow"},
			DenyGroups:  []string{"deny"},
			Mode:        modeZeroIP,
		},
		ListGroups: map[string]ListGroupConfig{
			"allow": {Sources: []string{allowFile}, Format: "auto"},
			"deny":  {Sources: []string{denyFile}, Format: "auto"},
		},
	}

	allow, deny, err := loadExactDomainsWithContext(context.Background(), cfg)
	if err != nil {
		t.Fatalf("loadExactDomainsWithContext returned error: %v", err)
	}
	if _, ok := allow["allow.example"]; !ok {
		t.Fatalf("allow set missing expected domain")
	}
	if _, ok := deny["deny.example"]; !ok {
		t.Fatalf("deny set missing expected domain")
	}
}

func TestLoadExactDomainsHTTPSource(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("deny.example\n"))
	}))
	defer srv.Close()

	cfg := &Config{
		Policy: PolicyConfig{
			DenyGroups: []string{"deny"},
		},
		ListGroups: map[string]ListGroupConfig{
			"deny": {
				Sources: []string{srv.URL},
				Format:  "auto",
			},
		},
		Loading: LoadingConfig{
			HTTPTimeout: time.Second,
			MaxBodySize: 1024,
		},
	}

	_, deny, err := loadExactDomainsWithContext(context.Background(), cfg)
	if err != nil {
		t.Fatalf("loadExactDomainsWithContext returned error: %v", err)
	}
	if _, ok := deny["deny.example"]; !ok {
		t.Fatalf("deny set missing expected domain from HTTP source")
	}
}

func TestLoadExactDomainsHTTPSourceMaxBodySize(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("deny.example\n", 16)))
	}))
	defer srv.Close()

	cfg := &Config{
		Policy: PolicyConfig{
			DenyGroups: []string{"deny"},
		},
		ListGroups: map[string]ListGroupConfig{
			"deny": {
				Sources: []string{srv.URL},
				Format:  "auto",
			},
		},
		Loading: LoadingConfig{
			HTTPTimeout: time.Second,
			MaxBodySize: 8,
		},
	}

	if _, _, err := loadExactDomainsWithContext(context.Background(), cfg); err == nil {
		t.Fatalf("expected loadExactDomainsWithContext to fail on max_body_size")
	}
}

func TestLoadExactDomainsHTTPSourceNoSizeLimit(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("deny.example\n", 128)))
	}))
	defer srv.Close()

	cfg := &Config{
		Policy: PolicyConfig{
			DenyGroups: []string{"deny"},
		},
		ListGroups: map[string]ListGroupConfig{
			"deny": {Sources: []string{srv.URL}, Format: "auto"},
		},
		Loading: LoadingConfig{
			HTTPTimeout: time.Second,
			MaxBodySize: 0,
		},
	}

	_, deny, err := loadExactDomainsWithContext(context.Background(), cfg)
	if err != nil {
		t.Fatalf("loadExactDomainsWithContext returned error: %v", err)
	}
	if _, ok := deny["deny.example"]; !ok {
		t.Fatalf("deny set missing expected domain")
	}
}

func TestLoadExactDomainsHTTPSourceStatusError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cfg := &Config{
		Policy: PolicyConfig{
			DenyGroups: []string{"deny"},
		},
		ListGroups: map[string]ListGroupConfig{
			"deny": {Sources: []string{srv.URL}, Format: "auto"},
		},
		Loading: LoadingConfig{
			HTTPTimeout: time.Second,
			MaxBodySize: 1024,
		},
	}

	_, _, err := loadExactDomainsWithContext(context.Background(), cfg)
	if err == nil {
		t.Fatalf("expected status error")
	}
	if !errors.Is(err, errUnexpectedHTTPStatus) {
		t.Fatalf("expected errUnexpectedHTTPStatus, got %v", err)
	}
}

func TestLoadExactDomainsFileURISource(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	denyFile := filepath.Join(tmp, "deny.txt")
	if err := os.WriteFile(denyFile, []byte("deny.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		Policy: PolicyConfig{
			DenyGroups: []string{"deny"},
		},
		ListGroups: map[string]ListGroupConfig{
			"deny": {
				Sources: []string{"file://" + denyFile},
				Format:  "auto",
			},
		},
	}

	_, deny, err := loadExactDomainsWithContext(context.Background(), cfg)
	if err != nil {
		t.Fatalf("loadExactDomainsWithContext returned error: %v", err)
	}
	if _, ok := deny["deny.example"]; !ok {
		t.Fatalf("deny set missing expected domain from file URI")
	}
}

func TestListEntriesMetricUpdatedFromLoad(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()

	denyFile := filepath.Join(tmp, "deny.txt")
	if err := os.WriteFile(denyFile, []byte("a.example\nb.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		PolicyName: "default",
		Policy: PolicyConfig{
			DenyGroups: []string{"deny"},
		},
		ListGroups: map[string]ListGroupConfig{
			"deny": {Sources: []string{denyFile}, Format: "domain"},
		},
	}

	_, _, err := loadExactDomainsWithContext(context.Background(), cfg)
	if err != nil {
		t.Fatalf("loadExactDomainsWithContext returned error: %v", err)
	}

	m := listEntries.WithLabelValues("default", "deny", "exact")
	if got := metricGaugeValue(t, m); got < 2 {
		t.Fatalf("expected list_entries >= 2, got %v", got)
	}
}

func metricGaugeValue(t *testing.T, g interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := g.Write(m); err != nil {
		t.Fatalf("failed to read metric: %v", err)
	}
	if m.Gauge == nil || m.Gauge.Value == nil {
		t.Fatalf("gauge metric was not set")
	}
	return *m.Gauge.Value
}
