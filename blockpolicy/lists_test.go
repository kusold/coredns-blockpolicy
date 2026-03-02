package blockpolicy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadDomainFileParsesDomainAndHosts(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "domains.txt")
	content := `# comment
ads.example
0.0.0.0 tracking.example
:: another.example
ads2.example # inline
0.0.0.0 tracking2.example # inline
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got := map[string]struct{}{}
	if err := loadDomainFile(path, got); err != nil {
		t.Fatalf("loadDomainFile failed: %v", err)
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

func TestLoadExactDomains(t *testing.T) {
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
			"allow": {Sources: []string{allowFile}},
			"deny":  {Sources: []string{denyFile}},
		},
	}

	allow, deny, err := loadExactDomains(cfg)
	if err != nil {
		t.Fatalf("loadExactDomains returned error: %v", err)
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
