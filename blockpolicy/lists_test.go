package blockpolicy

import (
	"os"
	"path/filepath"
	"testing"
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
		t.Fatalf("expected http source to fail in milestone 1")
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
