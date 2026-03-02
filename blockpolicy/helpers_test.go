package blockpolicy

import (
	"context"
	"errors"
	"net"
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

type errorNext struct {
	calls atomic.Int32
	err   error
}

func (*errorNext) Name() string { return "error" }

func (n *errorNext) ServeDNS(context.Context, dns.ResponseWriter, *dns.Msg) (int, error) {
	n.calls.Add(1)
	if n.err != nil {
		return dns.RcodeServerFailure, n.err
	}
	return dns.RcodeServerFailure, errors.New("forced next error")
}

var _ plugin.Handler = &noopNext{}
var _ plugin.Handler = &staticResponseNext{}
var _ plugin.Handler = &errorNext{}

type noopResponseWriter struct{}

func (*noopResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}

func (*noopResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 55300}
}

func (*noopResponseWriter) WriteMsg(*dns.Msg) error     { return nil }
func (*noopResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (*noopResponseWriter) Close() error                { return nil }
func (*noopResponseWriter) TsigStatus() error           { return nil }
func (*noopResponseWriter) TsigTimersOnly(bool)         {}
func (*noopResponseWriter) Hijack()                     {}
