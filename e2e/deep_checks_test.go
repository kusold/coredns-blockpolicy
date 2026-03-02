package e2e

import (
	"fmt"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestE2E_DeepCNAMEBlocking(t *testing.T) {
	t.Parallel()

	upstream := startCustomUpstream(t, func(q dns.Question, m *dns.Msg) {
		switch {
		case q.Qtype == dns.TypeA && q.Name == "example.com.":
			m.Answer = append(m.Answer,
				&dns.CNAME{
					Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "tracker.example.com.",
				},
				&dns.A{
					Hdr: dns.RR_Header{Name: "tracker.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("9.9.9.9").To4(),
				},
			)
		default:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4").To4(),
			})
		}
	})
	denyFile := writeTempList(t, "tracker.example.com")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
	})
	udp := startServer(t, corefile)

	resp := exchange(t, udp, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answer[0])
	}
	if got := a.A.String(); got != "0.0.0.0" {
		t.Fatalf("expected 0.0.0.0, got %s", got)
	}
}

func TestE2E_ResponseIPBlocking(t *testing.T) {
	t.Parallel()

	upstream := startCustomUpstream(t, func(q dns.Question, m *dns.Msg) {
		if q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("123.145.123.145").To4(),
			})
		}
	})
	denyFile := writeTempList(t, "123.145.123.145")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
	})
	udp := startServer(t, corefile)

	resp := exchange(t, udp, "safe.example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answer[0])
	}
	if got := a.A.String(); got != "0.0.0.0" {
		t.Fatalf("expected 0.0.0.0, got %s", got)
	}
}

func TestE2E_ResponseIPAllowlistPrecedence(t *testing.T) {
	t.Parallel()

	upstream := startCustomUpstream(t, func(q dns.Question, m *dns.Msg) {
		if q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("123.145.123.145").To4(),
			})
		}
	})
	denyFile := writeTempList(t, "123.145.123.145")
	allowFile := writeTempList(t, "123.145.123.145")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		AllowFile: allowFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
	})
	udp := startServer(t, corefile)

	resp := exchange(t, udp, "safe.example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answer[0])
	}
	if got := a.A.String(); got != "123.145.123.145" {
		t.Fatalf("expected allowlisted upstream IP, got %s", got)
	}
}

func TestE2E_ResponseIPBlockingAAAA(t *testing.T) {
	t.Parallel()

	upstream := startCustomUpstream(t, func(q dns.Question, m *dns.Msg) {
		if q.Qtype == dns.TypeAAAA {
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: net.ParseIP("2001:db8::10"),
			})
		}
	})
	denyFile := writeTempList(t, "2001:db8::10")

	corefile := buildCorefile(corefileParams{
		DenyFile:  denyFile,
		BlockMode: "zeroip",
		Upstream:  upstream,
	})
	udp := startServer(t, corefile)

	resp := exchange(t, udp, "safe.example.com", dns.TypeAAAA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("expected AAAA record, got %T", resp.Answer[0])
	}
	if got := aaaa.AAAA.String(); got != "::" {
		t.Fatalf("expected ::, got %s", got)
	}
}

func TestE2E_DeepChecksCanBeDisabledViaMatchingBlock(t *testing.T) {
	t.Parallel()

	upstream := startCustomUpstream(t, func(q dns.Question, m *dns.Msg) {
		if q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("123.145.123.145").To4(),
			})
		}
	})
	denyFile := writeTempList(t, "123.145.123.145")

	corefile := fmt.Sprintf(`.:0 {
  blockpolicy {
    policy default {
      deny_groups deny
      block_mode zeroip
      ttl 60s
    }
    use_policy default
    list_group deny {
      source %s
    }
    matching {
      exact true
      wildcard true
      regex true
      hosts_format true
      deep_cname false
      response_ip_lists false
    }
  }
  forward . %s
}
`, denyFile, upstream)

	udp := startServer(t, corefile)
	resp := exchange(t, udp, "safe.example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answer[0])
	}
	if got := a.A.String(); got != "123.145.123.145" {
		t.Fatalf("expected passthrough upstream IP, got %s", got)
	}
}

func startCustomUpstream(t *testing.T, answerFn func(q dns.Question, m *dns.Msg)) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if len(r.Question) > 0 {
			answerFn(r.Question[0], m)
		}
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{
		PacketConn: pc,
		Handler:    mux,
	}
	go server.ActivateAndServe()

	t.Cleanup(func() {
		_ = server.Shutdown()
	})

	return pc.LocalAddr().String()
}
