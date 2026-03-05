package e2e

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coredns/coredns/core/dnsserver"
	coretest "github.com/coredns/coredns/test"
	"github.com/miekg/dns"

	// Register the DNS server type with Caddy.
	_ "github.com/coredns/coredns/core"

	// Register only the built-in plugins we need for E2E tests.
	_ "github.com/coredns/coredns/plugin/forward"
	_ "github.com/coredns/coredns/plugin/metrics"

	// Register our plugin.
	_ "github.com/kusold/coredns-blockpolicy/blockpolicy"
)

func init() {
	// Insert "blockpolicy" into the Directives slice between "cache" and
	// "rewrite" so it runs after cache but before forward, matching the
	// recommended plugin chain order from the spec.
	dnsserver.Directives = insertDirective(dnsserver.Directives, "blockpolicy", "rewrite")
}

// insertDirective inserts directive into dirs immediately before the element
// named "before". If "before" is not found, directive is appended.
func insertDirective(dirs []string, directive, before string) []string {
	for i, d := range dirs {
		if d == before {
			out := make([]string, 0, len(dirs)+1)
			out = append(out, dirs[:i]...)
			out = append(out, directive)
			out = append(out, dirs[i:]...)
			return out
		}
	}
	return append(dirs, directive)
}

// corefileParams holds the parameters used to render a Corefile for testing.
type corefileParams struct {
	DenyFile  string // path to deny list file (required)
	AllowFile string // path to allow list file (optional)
	BlockMode string // "zeroip" or "nxdomain" (default: "zeroip")
	TTL       string // e.g. "42s" (default: "60s")
	Upstream  string // upstream DNS address (host:port from dnstest.Server)
	PromAddr  string // prometheus listen address (optional)
}

// buildCorefile renders a Corefile string from the given parameters.
func buildCorefile(p corefileParams) string {
	if p.BlockMode == "" {
		p.BlockMode = "zeroip"
	}
	if p.TTL == "" {
		p.TTL = "60s"
	}

	var sb strings.Builder
	sb.WriteString(".:0 {\n")

	if p.PromAddr != "" {
		fmt.Fprintf(&sb, "  prometheus %s\n", p.PromAddr)
	}

	sb.WriteString("  blockpolicy {\n")
	sb.WriteString("    policy default {\n")
	sb.WriteString("      deny_groups deny\n")
	if p.AllowFile != "" {
		sb.WriteString("      allow_groups allow\n")
	}
	fmt.Fprintf(&sb, "      block_mode %s\n", p.BlockMode)
	fmt.Fprintf(&sb, "      ttl %s\n", p.TTL)
	sb.WriteString("    }\n")
	sb.WriteString("    use_policy default\n")

	fmt.Fprintf(&sb, "    list_group deny {\n")
	fmt.Fprintf(&sb, "      source %s\n", p.DenyFile)
	sb.WriteString("    }\n")

	if p.AllowFile != "" {
		sb.WriteString("    list_group allow {\n")
		fmt.Fprintf(&sb, "      source %s\n", p.AllowFile)
		sb.WriteString("    }\n")
	}

	sb.WriteString("  }\n")

	if p.Upstream != "" {
		fmt.Fprintf(&sb, "  forward . %s\n", p.Upstream)
	}

	sb.WriteString("}\n")
	return sb.String()
}

// startServer starts a CoreDNS instance with the given Corefile and returns the
// UDP listen address. The server is automatically stopped when the test ends.
func startServer(t *testing.T, corefile string) string {
	t.Helper()
	instance, udp, _, err := coretest.CoreDNSServerAndPorts(corefile)
	if err != nil {
		t.Fatalf("failed to start CoreDNS: %v", err)
	}
	t.Cleanup(func() { instance.Stop() })
	return udp
}

// startUpstream starts a lightweight DNS server that answers all A queries with
// 1.2.3.4 and AAAA queries with 2001:db8::1, so passthrough is distinguishable
// from blocked (which uses 0.0.0.0 / ::).
func startUpstream(t *testing.T) string {
	t.Helper()
	server := newUpstreamServer()
	t.Cleanup(func() { server.Close() })
	return server.Addr
}

// upstreamServer wraps a dns.Server for test upstream use.
type upstreamServer struct {
	Addr   string
	server *dns.Server
}

func newUpstreamServer() *upstreamServer {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(fmt.Sprintf("failed to listen: %v", err))
	}

	s := &upstreamServer{
		Addr: pc.LocalAddr().String(),
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if len(r.Question) > 0 {
			q := r.Question[0]
			switch q.Qtype {
			case dns.TypeA:
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
					A:   net.ParseIP("1.2.3.4").To4(),
				})
			case dns.TypeAAAA:
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600},
					AAAA: net.ParseIP("2001:db8::1"),
				})
			case dns.TypeTXT:
				m.Answer = append(m.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
					Txt: []string{"upstream"},
				})
			}
		}
		w.WriteMsg(m)
	})

	s.server = &dns.Server{
		PacketConn: pc,
		Handler:    mux,
	}
	go s.server.ActivateAndServe()
	return s
}

func (s *upstreamServer) Close() {
	s.server.Shutdown()
}

// exchange sends a DNS query and returns the response. It fails the test on error.
func exchange(t *testing.T, addr, qname string, qtype uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	resp, err := dns.Exchange(m, addr)
	if err != nil {
		t.Fatalf("DNS exchange for %s/%s to %s failed: %v", qname, dns.TypeToString[qtype], addr, err)
	}
	return resp
}

// writeTempList writes the given domains (one per line) to a temp file and
// returns the file path.
func writeTempList(t *testing.T, domains ...string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	content := strings.Join(domains, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write temp list: %v", err)
	}
	return path
}

// writeTempFile writes arbitrary content to a temp file and returns the path.
func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return path
}

// testdataPath returns the absolute path to a file in the testdata directory.
func testdataPath(t *testing.T, name string) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("failed to resolve testdata path: %v", err)
	}
	return path
}
