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
	"regexp"
	"sort"
	"strings"
	"sync"

	blockyparsers "github.com/0xERR0R/blocky/lists/parsers"
	blockytrie "github.com/0xERR0R/blocky/trie"
	"golang.org/x/sync/errgroup"
)

var errUnexpectedHTTPStatus = errors.New("unexpected HTTP status code")

func loadMatcherSetsWithContext(ctx context.Context, cfg *Config) (matcherSet, matcherSet, error) {
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

func (l *listLoader) load(ctx context.Context) (matcherSet, matcherSet, error) {
	allow := newEntryBuilder()
	deny := newEntryBuilder()

	for _, groupName := range l.cfg.Policy.AllowGroups {
		if err := l.loadGroupIntoSet(ctx, groupName, l.cfg.ListGroups[groupName], allow); err != nil {
			return matcherSet{}, matcherSet{}, fmt.Errorf("load allow group %q: %w", groupName, err)
		}
	}
	for _, groupName := range l.cfg.Policy.DenyGroups {
		if err := l.loadGroupIntoSet(ctx, groupName, l.cfg.ListGroups[groupName], deny); err != nil {
			return matcherSet{}, matcherSet{}, fmt.Errorf("load deny group %q: %w", groupName, err)
		}
	}

	return allow.toMatcherSet(), deny.toMatcherSet(), nil
}

func (l *listLoader) loadGroupIntoSet(ctx context.Context, groupName string, group ListGroupConfig, out *entryBuilder) error {
	groupSet := newEntryBuilder()
	var mu sync.Mutex
	g, groupCtx := errgroup.WithContext(ctx)
	for _, src := range group.Sources {
		src := src
		g.Go(func() error {
			sourceSet := newEntryBuilder()
			if err := l.loadSourceIntoSet(groupCtx, groupName, group.Format, src, sourceSet); err != nil {
				return err
			}
			mu.Lock()
			groupSet.merge(sourceSet)
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	out.merge(groupSet)
	listEntries.WithLabelValues(l.cfg.PolicyName, groupName, "exact").Set(float64(len(groupSet.exact)))
	listEntries.WithLabelValues(l.cfg.PolicyName, groupName, "wildcard").Set(float64(len(groupSet.wildcard)))
	listEntries.WithLabelValues(l.cfg.PolicyName, groupName, "regex").Set(float64(len(groupSet.regex)))
	listEntries.WithLabelValues(l.cfg.PolicyName, groupName, "ip").Set(float64(len(groupSet.ips)))

	return nil
}

func (l *listLoader) loadSourceIntoSet(ctx context.Context, groupName, format, src string, out *entryBuilder) error {
	reader, err := l.openSource(ctx, src)
	if err != nil {
		return fmt.Errorf("open source %q for group %q: %w", src, groupName, err)
	}
	defer reader.Close()

	warn := func(err error) {
		log.Warningf("skip invalid %s entry from %s: %v", format, src, err)
		errorsTotal.WithLabelValues("parse", "entry").Inc()
	}

	if err := parseEntriesWithBlocky(ctx, format, reader, out, effectiveMatchingConfig(l.cfg.Matching), warn); err != nil {
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

func parseEntriesWithBlocky(
	ctx context.Context,
	format string,
	reader io.Reader,
	out *entryBuilder,
	matching MatchingConfig,
	warn func(error),
) error {
	if warn == nil {
		warn = func(error) {}
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
				addListEntry(out, host, matching, warn)
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
			addListEntry(out, entry.Name, matching, warn)
			for _, alias := range entry.Aliases {
				addListEntry(out, alias, matching, warn)
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
			addListEntry(out, entry.String(), matching, warn)
			return nil
		})

	case "wildcard":
		p := blockyparsers.AllowErrors(blockyparsers.LinesAs[*blockyparsers.WildcardEntry](reader), blockyparsers.NoErrorLimit)
		p.OnErr(warn)
		return blockyparsers.ForEach[*blockyparsers.WildcardEntry](ctx, p, func(entry *blockyparsers.WildcardEntry) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			addListEntry(out, entry.String(), matching, warn)
			return nil
		})

	case "regex":
		p := blockyparsers.AllowErrors(blockyparsers.Lines(reader), blockyparsers.NoErrorLimit)
		p.OnErr(warn)
		return blockyparsers.ForEach[string](ctx, p, func(entry string) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			addRegexEntry(out, entry, matching.Regex, warn)
			return nil
		})

	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func addListEntry(out *entryBuilder, entry string, matching MatchingConfig, warn func(error)) {
	if isRegexListEntry(entry) {
		addRegexEntry(out, entry, matching.Regex, warn)
		return
	}
	if strings.Contains(entry, "*") {
		addWildcardEntry(out, entry, matching.Wildcard, warn)
		return
	}
	if addIPEntry(out.ips, entry) {
		return
	}
	if !matching.Exact {
		return
	}
	addExactEntry(out.exact, entry)
}

func addExactEntry(out map[string]struct{}, entry string) {
	normalized := normalizeExactListEntry(entry)
	if normalized == "" || net.ParseIP(normalized) != nil {
		return
	}
	out[normalized] = struct{}{}
}

func addIPEntry(out map[string]struct{}, entry string) bool {
	ip := net.ParseIP(strings.TrimSpace(entry))
	if ip == nil {
		return false
	}
	out[ip.String()] = struct{}{}
	return true
}

func addWildcardEntry(out *entryBuilder, entry string, enabled bool, warn func(error)) {
	if !enabled {
		return
	}
	normalized, err := normalizeWildcardListEntry(entry)
	if err != nil {
		warn(err)
		return
	}
	out.wildcard[normalized] = struct{}{}
}

func addRegexEntry(out *entryBuilder, entry string, enabled bool, warn func(error)) {
	if !enabled {
		return
	}
	pattern, err := normalizeRegexListEntry(entry)
	if err != nil {
		warn(err)
		return
	}
	if _, ok := out.regex[pattern]; ok {
		return
	}

	compiled, err := regexp.Compile(pattern)
	if err != nil {
		warn(fmt.Errorf("invalid regex %q: %w", entry, err))
		return
	}
	out.regex[pattern] = compiled
}

func normalizeWildcardListEntry(entry string) (string, error) {
	entry = strings.TrimSpace(strings.ToLower(entry))
	globCount := strings.Count(entry, "*")
	if globCount == 0 {
		return "", fmt.Errorf("unsupported wildcard %q: must contain '*'", entry)
	}
	if !strings.HasPrefix(entry, "*.") || globCount > 1 {
		return "", fmt.Errorf("unsupported wildcard %q: must start with '*.' and contain no other '*'", entry)
	}

	normalized := strings.TrimPrefix(entry, "*")
	normalized = strings.Trim(normalized, ".")
	if normalized == "" {
		return "", fmt.Errorf("unsupported wildcard %q: empty wildcard domain", entry)
	}
	return normalized, nil
}

func normalizeRegexListEntry(entry string) (string, error) {
	entry = strings.TrimSpace(entry)
	if !isRegexListEntry(entry) {
		return "", fmt.Errorf("unsupported regex %q: must be enclosed by '/'", entry)
	}
	return strings.TrimSpace(entry[1 : len(entry)-1]), nil
}

func isRegexListEntry(entry string) bool {
	entry = strings.TrimSpace(entry)
	return len(entry) >= 2 && strings.HasPrefix(entry, "/") && strings.HasSuffix(entry, "/")
}

type entryBuilder struct {
	exact    map[string]struct{}
	wildcard map[string]struct{}
	regex    map[string]*regexp.Regexp
	ips      map[string]struct{}
}

func newEntryBuilder() *entryBuilder {
	return &entryBuilder{
		exact:    map[string]struct{}{},
		wildcard: map[string]struct{}{},
		regex:    map[string]*regexp.Regexp{},
		ips:      map[string]struct{}{},
	}
}

func (e *entryBuilder) merge(other *entryBuilder) {
	for entry := range other.exact {
		e.exact[entry] = struct{}{}
	}
	for entry := range other.wildcard {
		e.wildcard[entry] = struct{}{}
	}
	for pattern, compiled := range other.regex {
		e.regex[pattern] = compiled
	}
	for ip := range other.ips {
		e.ips[ip] = struct{}{}
	}
}

func (e *entryBuilder) toMatcherSet() matcherSet {
	wildcardTrie := blockytrie.NewTrie(blockytrie.SplitTLD)
	for entry := range e.wildcard {
		wildcardTrie.Insert(entry)
	}

	patterns := make([]string, 0, len(e.regex))
	for pattern := range e.regex {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		compiled = append(compiled, e.regex[pattern])
	}

	return matcherSet{
		exact:    e.exact,
		wildcard: wildcardTrie,
		regex:    compiled,
		ips:      e.ips,
	}
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
