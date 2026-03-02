package blockpolicy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	blockyparsers "github.com/0xERR0R/blocky/lists/parsers"
)

func loadExactDomains(cfg *Config) (map[string]struct{}, map[string]struct{}, error) {
	return loadExactDomainsWithContext(context.Background(), cfg)
}

func loadExactDomainsWithContext(ctx context.Context, cfg *Config) (map[string]struct{}, map[string]struct{}, error) {
	loader := newListLoader(cfg)
	return loader.load(ctx)
}

type listLoader struct {
	cfg        *Config
	httpClient *http.Client
}

func newListLoader(cfg *Config) *listLoader {
	return &listLoader{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Loading.HTTPTimeout,
		},
	}
}

func (l *listLoader) load(ctx context.Context) (map[string]struct{}, map[string]struct{}, error) {
	allow := make(map[string]struct{})
	deny := make(map[string]struct{})

	for _, groupName := range l.cfg.Policy.AllowGroups {
		if err := l.loadGroupIntoSet(ctx, groupName, l.cfg.ListGroups[groupName], allow); err != nil {
			return nil, nil, fmt.Errorf("load allow group %q: %w", groupName, err)
		}
	}
	for _, groupName := range l.cfg.Policy.DenyGroups {
		if err := l.loadGroupIntoSet(ctx, groupName, l.cfg.ListGroups[groupName], deny); err != nil {
			return nil, nil, fmt.Errorf("load deny group %q: %w", groupName, err)
		}
	}

	return allow, deny, nil
}

func (l *listLoader) loadGroupIntoSet(ctx context.Context, groupName string, group ListGroupConfig, out map[string]struct{}) error {
	format := group.Format
	if format == "" {
		format = "auto"
	}
	for _, src := range group.Sources {
		if err := l.loadSourceIntoSet(ctx, groupName, format, src, out); err != nil {
			return err
		}
	}
	return nil
}

func (l *listLoader) loadSourceIntoSet(ctx context.Context, groupName, format, src string, out map[string]struct{}) error {
	reader, err := l.openSource(ctx, src)
	if err != nil {
		return fmt.Errorf("open source %q for group %q: %w", src, groupName, err)
	}
	defer reader.Close()

	if err := parseDomainsWithBlocky(ctx, format, src, reader, out); err != nil {
		return fmt.Errorf("parse source %q for group %q: %w", src, groupName, err)
	}
	return nil
}

func (l *listLoader) openSource(ctx context.Context, src string) (io.ReadCloser, error) {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		resp, err := l.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			resp.Body.Close()
			return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
		}
		return limitReaderFromBody(resp.Body, l.cfg.Loading.MaxBodySize)
	}

	path, err := sourcePath(src)
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}

func limitReaderFromBody(body io.ReadCloser, maxBodySize int64) (io.ReadCloser, error) {
	if maxBodySize <= 0 {
		return body, nil
	}

	defer body.Close()

	payload, err := io.ReadAll(io.LimitReader(body, maxBodySize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > maxBodySize {
		return nil, fmt.Errorf("response body exceeds max_body_size (%d bytes)", maxBodySize)
	}

	return io.NopCloser(bytes.NewReader(payload)), nil
}

func parseDomainsWithBlocky(ctx context.Context, format, source string, reader io.Reader, out map[string]struct{}) error {
	switch format {
	case "auto", "hosts":
		p := blockyparsers.AllowErrors(blockyparsers.Hosts(reader), blockyparsers.NoErrorLimit)
		p.OnErr(func(err error) {
			log.Warningf("skip invalid %s entry from %s: %v", format, source, err)
		})
		return blockyparsers.ForEach[*blockyparsers.HostsIterator](ctx, p, func(hosts *blockyparsers.HostsIterator) error {
			return hosts.ForEach(func(host string) error {
				normalized := normalizeExactListEntry(host)
				if normalized == "" || net.ParseIP(normalized) != nil {
					return nil
				}
				out[normalized] = struct{}{}
				return nil
			})
		})
	case "domain":
		p := blockyparsers.AllowErrors(blockyparsers.HostList(reader), blockyparsers.NoErrorLimit)
		p.OnErr(func(err error) {
			log.Warningf("skip invalid %s entry from %s: %v", format, source, err)
		})
		return blockyparsers.ForEach[*blockyparsers.HostListEntry](ctx, p, func(entry *blockyparsers.HostListEntry) error {
			normalized := normalizeExactListEntry(entry.String())
			if normalized == "" || net.ParseIP(normalized) != nil {
				return nil
			}
			out[normalized] = struct{}{}
			return nil
		})
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func loadDomainFile(path string, out map[string]struct{}) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	if err := parseDomainsWithBlocky(context.Background(), "auto", path, f, out); err != nil {
		return fmt.Errorf("scan %q: %w", path, err)
	}
	return nil
}

func sourcePath(src string) (string, error) {
	if strings.HasPrefix(src, "file://") {
		u, err := url.Parse(src)
		if err != nil {
			return "", fmt.Errorf("parse source %q: %w", src, err)
		}
		return u.Path, nil
	}
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		return "", fmt.Errorf("source %q is not a local file path", src)
	}
	return src, nil
}
