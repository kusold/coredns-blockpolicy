package blockpolicy

import (
	"context"
	"sync/atomic"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

type noopNext struct {
	calls atomic.Int32
}

func (*noopNext) Name() string { return "noop" }

func (n *noopNext) ServeDNS(context.Context, dns.ResponseWriter, *dns.Msg) (int, error) {
	n.calls.Add(1)
	return dns.RcodeSuccess, nil
}

type staticResponseNext struct {
	calls atomic.Int32
	msg   *dns.Msg
}

func (*staticResponseNext) Name() string { return "static" }

func (n *staticResponseNext) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	n.calls.Add(1)
	msg := new(dns.Msg)
	if n.msg != nil {
		msg = n.msg.Copy()
	} else {
		msg.SetReply(r)
	}
	if err := w.WriteMsg(msg); err != nil {
		return dns.RcodeServerFailure, err
	}
	return msg.Rcode, nil
}

var _ plugin.Handler = &noopNext{}
var _ plugin.Handler = &staticResponseNext{}
