package blockpolicy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	blockyparsers "github.com/0xERR0R/blocky/lists/parsers"
	"golang.org/x/sync/errgroup"
)

var errUnexpectedHTTPStatus = errors.New("unexpected HTTP status code")

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
	groupSet := make(map[string]struct{})
	var mu sync.Mutex
	g, groupCtx := errgroup.WithContext(ctx)
	for _, src := range group.Sources {
		src := src
		g.Go(func() error {
			sourceSet := make(map[string]struct{})
			if err := l.loadSourceIntoSet(groupCtx, groupName, group.Format, src, sourceSet); err != nil {
				return err
			}
			mu.Lock()
			for entry := range sourceSet {
				groupSet[entry] = struct{}{}
			}
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	for entry := range groupSet {
		out[entry] = struct{}{}
	}
	listEntries.WithLabelValues(l.cfg.PolicyName, groupName, "exact").Set(float64(len(groupSet)))

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
			return nil, fmt.Errorf("%w: %d", errUnexpectedHTTPStatus, resp.StatusCode)
		}

		return newMaxBodySizeReadCloser(resp.Body, l.cfg.Loading.MaxBodySize), nil
	}

	path, err := sourcePath(src)
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}

func parseDomainsWithBlocky(ctx context.Context, format, source string, reader io.Reader, out map[string]struct{}) error {
	warn := func(err error) {
		log.Warningf("skip invalid %s entry from %s: %v", format, source, err)
	}

	switch format {
	case "auto":
		p := blockyparsers.AllowErrors(blockyparsers.Hosts(reader), blockyparsers.NoErrorLimit)
		p.OnErr(warn)
		return blockyparsers.ForEach[*blockyparsers.HostsIterator](ctx, p, func(hosts *blockyparsers.HostsIterator) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return hosts.ForEach(func(host string) error {
				addExactEntry(out, host)
				return nil
			})
		})

	case "hosts":
		p := blockyparsers.AllowErrors(blockyparsers.HostsFile(reader), blockyparsers.NoErrorLimit)
		p.OnErr(warn)
		return blockyparsers.ForEach[*blockyparsers.HostsFileEntry](ctx, p, func(entry *blockyparsers.HostsFileEntry) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			addExactEntry(out, entry.Name)
			for _, alias := range entry.Aliases {
				addExactEntry(out, alias)
			}
			return nil
		})

	case "domain":
		p := blockyparsers.AllowErrors(blockyparsers.HostList(reader), blockyparsers.NoErrorLimit)
		p.OnErr(warn)
		return blockyparsers.ForEach[*blockyparsers.HostListEntry](ctx, p, func(entry *blockyparsers.HostListEntry) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			addExactEntry(out, entry.String())
			return nil
		})

	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func addExactEntry(out map[string]struct{}, entry string) {
	normalized := normalizeExactListEntry(entry)
	if normalized == "" || net.ParseIP(normalized) != nil {
		return
	}
	out[normalized] = struct{}{}
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

type maxBodySizeReadCloser struct {
	io.ReadCloser
	maxBodySize int64
	bytesRead   int64
}

func newMaxBodySizeReadCloser(inner io.ReadCloser, maxBodySize int64) io.ReadCloser {
	return &maxBodySizeReadCloser{
		ReadCloser:  inner,
		maxBodySize: maxBodySize,
	}
}

func (r *maxBodySizeReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	r.bytesRead += int64(n)
	if r.maxBodySize > 0 && r.bytesRead > r.maxBodySize {
		return n, fmt.Errorf("response body exceeds max_body_size (%d bytes)", r.maxBodySize)
	}
	return n, err
}
