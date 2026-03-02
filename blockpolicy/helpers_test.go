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

var _ plugin.Handler = &noopNext{}
