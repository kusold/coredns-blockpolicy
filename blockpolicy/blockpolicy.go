package blockpolicy

import (
	"context"
	"errors"
	"net"
	"strconv"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metadata"
	"github.com/miekg/dns"
)

type BlockPolicy struct {
	Next plugin.Handler

	policyName string
	ttl        uint32
	engine     *Engine
}

func New(next plugin.Handler, cfg *Config, allow, deny map[string]struct{}) *BlockPolicy {
	return &BlockPolicy{
		Next:       next,
		policyName: cfg.PolicyName,
		ttl:        uint32(cfg.Policy.TTL.Seconds()),
		engine:     NewEngine(cfg.Policy.Mode, allow, deny),
	}
}

func (b *BlockPolicy) Name() string {
	return "blockpolicy"
}

func (b *BlockPolicy) Ready() bool {
	return b.engine != nil
}

func (b *BlockPolicy) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	labels := labelValues(ctx, b.policyName, w)

	if len(r.Question) == 0 {
		queriesTotal.WithLabelValues(labels.server, labels.zone, labels.view, labels.policy, "none").Inc()
		allowedTotal.WithLabelValues(labels.server, labels.zone, labels.view, labels.policy, "empty_question").Inc()
		setMetadata(ctx, b.policyName, actionAllow, "empty_question", "")
		return plugin.NextOrFailure(b.Name(), b.Next, ctx, w, r)
	}

	q := r.Question[0]
	qtype := dns.TypeToString[q.Qtype]
	queriesTotal.WithLabelValues(labels.server, labels.zone, labels.view, labels.policy, qtype).Inc()

	decision := b.engine.Evaluate(q.Name, queryTypeFromDNS(q.Qtype))
	if decision.Action == actionAllow {
		allowedTotal.WithLabelValues(labels.server, labels.zone, labels.view, labels.policy, decision.Reason).Inc()
		setMetadata(ctx, b.policyName, decision.Action, decision.Reason, "")
		return plugin.NextOrFailure(b.Name(), b.Next, ctx, w, r)
	}

	msg, err := b.blockResponse(r, decision)
	if err != nil {
		return dns.RcodeServerFailure, err
	}
	if err := w.WriteMsg(msg); err != nil {
		return dns.RcodeServerFailure, err
	}
	blockedTotal.WithLabelValues(
		labels.server,
		labels.zone,
		labels.view,
		labels.policy,
		decision.Reason,
		string(decision.Mode),
		strconv.Itoa(msg.Rcode),
	).Inc()
	setMetadata(ctx, b.policyName, decision.Action, decision.Reason, string(decision.Mode))
	return msg.Rcode, nil
}

func (b *BlockPolicy) blockResponse(r *dns.Msg, d Decision) (*dns.Msg, error) {
	q := r.Question[0]
	m := new(dns.Msg)
	m.SetReply(r)

	if d.Code == codeNXDomain {
		m.Rcode = dns.RcodeNameError
		return m, nil
	}

	switch q.Qtype {
	case dns.TypeA:
		ip := net.ParseIP(d.IP)
		if ip == nil || ip.To4() == nil {
			return nil, errors.New("invalid synthetic IPv4 address")
		}
		m.Rcode = dns.RcodeSuccess
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: b.ttl},
			A:   ip.To4(),
		})
	case dns.TypeAAAA:
		ip := net.ParseIP(d.IP)
		if ip == nil || ip.To16() == nil {
			return nil, errors.New("invalid synthetic IPv6 address")
		}
		m.Rcode = dns.RcodeSuccess
		m.Answer = append(m.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: b.ttl},
			AAAA: ip,
		})
	default:
		m.Rcode = dns.RcodeNameError
	}

	return m, nil
}

type metricLabels struct {
	server string
	zone   string
	view   string
	policy string
}

func labelValues(ctx context.Context, policy string, w dns.ResponseWriter) metricLabels {
	zone := "."
	view := "default"
	if vf := metadata.ValueFunc(ctx, "view/name"); vf != nil {
		if v := vf(); v != "" {
			view = v
		}
	}
	server := "unknown"
	if w != nil && w.LocalAddr() != nil {
		server = w.LocalAddr().String()
	}
	if server == "" {
		server = "unknown"
	}

	return metricLabels{server: server, zone: zone, view: view, policy: policy}
}

func queryTypeFromDNS(t uint16) QueryType {
	switch t {
	case dns.TypeA:
		return queryTypeA
	case dns.TypeAAAA:
		return queryTypeAAAA
	default:
		return queryTypeOther
	}
}

func setMetadata(ctx context.Context, policy string, action decisionAction, reason, mode string) {
	// If the metadata plugin is not present in the CoreDNS chain, SetValueFunc is a no-op.
	metadata.SetValueFunc(ctx, "blockpolicy/policy", func() string { return policy })
	metadata.SetValueFunc(ctx, "blockpolicy/action", func() string { return string(action) })
	metadata.SetValueFunc(ctx, "blockpolicy/reason", func() string { return reason })
	metadata.SetValueFunc(ctx, "blockpolicy/mode", func() string { return mode })
}
