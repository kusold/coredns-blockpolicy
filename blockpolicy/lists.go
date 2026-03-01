package blockpolicy

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

func loadExactDomains(cfg *Config) (map[string]struct{}, map[string]struct{}, error) {
	allow := make(map[string]struct{})
	deny := make(map[string]struct{})

	for _, g := range cfg.Policy.AllowGroups {
		if err := loadGroupIntoSet(cfg.ListGroups[g], allow); err != nil {
			return nil, nil, fmt.Errorf("load allow group %q: %w", g, err)
		}
	}
	for _, g := range cfg.Policy.DenyGroups {
		if err := loadGroupIntoSet(cfg.ListGroups[g], deny); err != nil {
			return nil, nil, fmt.Errorf("load deny group %q: %w", g, err)
		}
	}

	return allow, deny, nil
}

func loadGroupIntoSet(group ListGroupConfig, out map[string]struct{}) error {
	for _, src := range group.Sources {
		path, err := sourcePath(src)
		if err != nil {
			return err
		}
		if err := loadDomainFile(path, out); err != nil {
			return err
		}
	}
	return nil
}

func sourcePath(src string) (string, error) {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		return "", fmt.Errorf("http(s) source %q not supported in milestone 1", src)
	}
	if strings.HasPrefix(src, "file://") {
		u, err := url.Parse(src)
		if err != nil {
			return "", fmt.Errorf("parse source %q: %w", src, err)
		}
		return u.Path, nil
	}
	return src, nil
}

func loadDomainFile(path string, out map[string]struct{}) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		// hosts-style line: "0.0.0.0 domain.tld"
		if ip := net.ParseIP(fields[0]); ip != nil {
			for i := 1; i < len(fields); i++ {
				name := normalizeName(fields[i])
				if name != "" {
					out[name] = struct{}{}
				}
			}
			continue
		}

		name := normalizeName(fields[0])
		if name != "" {
			out[name] = struct{}{}
		}
	}

	if err := s.Err(); err != nil {
		return fmt.Errorf("scan %q: %w", path, err)
	}
	return nil
}
