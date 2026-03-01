//go:build coredns

package blockpolicy

import (
	"context"
	"fmt"
	"net"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

type BlockPolicy struct {
	Next plugin.Handler

	policyName string
	mode       blockMode
	ttl        uint32
	allow      map[string]struct{}
	deny       map[string]struct{}
}

func New(next plugin.Handler, cfg *Config, allow, deny map[string]struct{}) *BlockPolicy {
	registerMetrics()
	return &BlockPolicy{
		Next:       next,
		policyName: cfg.PolicyName,
		mode:       cfg.Policy.Mode,
		ttl:        uint32(cfg.Policy.TTL.Seconds()),
		allow:      allow,
		deny:       deny,
	}
}

func (b *BlockPolicy) Name() string {
	return "blockpolicy"
}

func (b *BlockPolicy) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	queriesTotal.WithLabelValues(b.policyName).Inc()
	if len(r.Question) == 0 {
		return plugin.NextOrFailure(b.Name(), b.Next, ctx, w, r)
	}

	q := r.Question[0]
	name := normalizeName(q.Name)
	if _, allowed := b.allow[name]; allowed {
		return plugin.NextOrFailure(b.Name(), b.Next, ctx, w, r)
	}
	if _, denied := b.deny[name]; denied {
		blockedTotal.WithLabelValues(b.policyName, string(b.mode), "denylist").Inc()
		msg, rcode, err := b.blockResponse(r)
		if err != nil {
			return dns.RcodeServerFailure, err
		}
		if err := w.WriteMsg(msg); err != nil {
			return dns.RcodeServerFailure, err
		}
		return rcode, nil
	}

	return plugin.NextOrFailure(b.Name(), b.Next, ctx, w, r)
}

func (b *BlockPolicy) blockResponse(r *dns.Msg) (*dns.Msg, int, error) {
	q := r.Question[0]

	if b.mode == modeNXDomain {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		return m, dns.RcodeNameError, nil
	}

	// zeroip mode
	switch q.Qtype {
	case dns.TypeA:
		m := new(dns.Msg)
		m.SetReply(r)
		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN A %s", q.Name, b.ttl, net.IPv4zero.String()))
		if err != nil {
			return nil, 0, err
		}
		m.Answer = append(m.Answer, rr)
		return m, dns.RcodeSuccess, nil
	case dns.TypeAAAA:
		m := new(dns.Msg)
		m.SetReply(r)
		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN AAAA %s", q.Name, b.ttl, net.IPv6zero.String()))
		if err != nil {
			return nil, 0, err
		}
		m.Answer = append(m.Answer, rr)
		return m, dns.RcodeSuccess, nil
	default:
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		return m, dns.RcodeNameError, nil
	}
}
