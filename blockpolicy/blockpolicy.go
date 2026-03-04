package blockpolicy

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metadata"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

type BlockPolicy struct {
	Next plugin.Handler

	Zones []string
	Fall  fall.F

	policyName string
	ttl        uint32
	mode       blockMode
	deepCNAME  bool
	responseIP bool

	engine atomic.Pointer[Engine]

	loader        *listLoader
	refreshPeriod time.Duration

	// consecutiveRefreshErrors tracks sequential refresh failures for health reporting.
	consecutiveRefreshErrors atomic.Int64

	startOnce sync.Once
	stopOnce  sync.Once
	stateMu   sync.Mutex
	started   bool
	stopCh    chan struct{}
	doneCh    chan struct{}
}

const shutdownWaitTimeout = 5 * time.Second

func NewWithMatchers(next plugin.Handler, cfg *Config, allow, deny matcherSet) *BlockPolicy {
	matching := cfg.Matching
	if !cfg.matchingConfigured {
		matching = effectiveMatchingConfig(matching)
	}

	b := &BlockPolicy{
		Next:       next,
		Fall:       cfg.Fall,
		policyName: cfg.PolicyName,
		ttl:        uint32(cfg.Policy.TTL.Seconds()),
		mode:       cfg.Policy.Mode,
		deepCNAME:  matching.DeepCNAME,
		responseIP: matching.ResponseIPLists,

		refreshPeriod: cfg.Loading.RefreshPeriod,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
	b.engine.Store(NewEngineWithMatchers(cfg.Policy.Mode, allow, deny))
	if len(cfg.ListGroups) > 0 {
		b.loader = newListLoader(cfg)
	}
	return b
}

func (b *BlockPolicy) Name() string {
	return "blockpolicy"
}

func (b *BlockPolicy) Ready() bool {
	return b.engine.Load() != nil
}

// maxConsecutiveRefreshErrors is the threshold after which the plugin reports
// itself as unhealthy. The last-good snapshot continues serving queries.
const maxConsecutiveRefreshErrors = 3

// Healthy reports whether the plugin is operating normally. It returns false
// when the background refresh loop has failed maxConsecutiveRefreshErrors times
// in a row, indicating a persistent problem with list sources.
func (b *BlockPolicy) Healthy() bool {
	return b.consecutiveRefreshErrors.Load() < int64(maxConsecutiveRefreshErrors)
}

func (b *BlockPolicy) OnStartup() error {
	if b.loader == nil || b.refreshPeriod <= 0 {
		return nil
	}
	b.startOnce.Do(func() {
		b.stateMu.Lock()
		b.started = true
		b.stateMu.Unlock()
		go b.refreshLoop()
	})
	return nil
}

func (b *BlockPolicy) OnShutdown() error {
	b.stateMu.Lock()
	started := b.started
	b.stateMu.Unlock()
	if !started {
		return nil
	}
	b.stopOnce.Do(func() {
		close(b.stopCh)
	})
	select {
	case <-b.doneCh:
	case <-time.After(shutdownWaitTimeout):
		log.Warningf("timed out waiting for refresh loop shutdown after %s", shutdownWaitTimeout)
	}
	return nil
}

func (b *BlockPolicy) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	zone := plugin.Zones(b.Zones).Matches(state.Name())
	if zone == "" {
		return plugin.NextOrFailure(b.Name(), b.Next, ctx, w, r)
	}

	labels := labelValues(ctx, b.policyName, zone, w)

	if len(r.Question) == 0 {
		queriesTotal.WithLabelValues(labels.server, labels.zone, labels.view, labels.policy, "none").Inc()
		allowedTotal.WithLabelValues(labels.server, labels.zone, labels.view, labels.policy, "empty_question").Inc()
		setMetadata(ctx, b.policyName, actionAllow, "empty_question", "")
		return plugin.NextOrFailure(b.Name(), b.Next, ctx, w, r)
	}

	q := r.Question[0]
	qtype := dns.TypeToString[q.Qtype]
	queriesTotal.WithLabelValues(labels.server, labels.zone, labels.view, labels.policy, qtype).Inc()

	engine := b.currentEngine()
	queryType := queryTypeFromDNS(q.Qtype)
	matchStart := time.Now()
	decision := engine.Evaluate(q.Name, queryType)
	matchDuration.WithLabelValues("direct").Observe(time.Since(matchStart).Seconds())

	if decision.Action == actionAllow {
		if decision.Reason == "allowlist" || !(b.deepCNAME || b.responseIP) {
			b.recordAllowed(ctx, labels, decision.Reason)
			return plugin.NextOrFailure(b.Name(), b.Next, ctx, w, r)
		}
	}

	if decision.Action == actionAllow {
		finalDecision, rcode, err := b.resolveWithDeepChecks(ctx, w, r, engine, queryType)
		if err != nil {
			return rcode, err
		}
		if finalDecision.Action == actionAllow {
			b.recordAllowed(ctx, labels, "passthrough")
			return rcode, nil
		}
		return b.writeBlocked(ctx, w, r, labels, finalDecision)
	}

	if b.Fall.Through(state.Name()) {
		return plugin.NextOrFailure(b.Name(), b.Next, ctx, w, r)
	}

	return b.writeBlocked(ctx, w, r, labels, decision)
}

func (b *BlockPolicy) recordAllowed(ctx context.Context, labels metricLabels, reason string) {
	allowedTotal.WithLabelValues(labels.server, labels.zone, labels.view, labels.policy, reason).Inc()
	setMetadata(ctx, b.policyName, actionAllow, reason, "")
}

func (b *BlockPolicy) writeBlocked(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, labels metricLabels, decision Decision) (int, error) {
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

func (b *BlockPolicy) resolveWithDeepChecks(
	ctx context.Context,
	w dns.ResponseWriter,
	r *dns.Msg,
	engine *Engine,
	qtype QueryType,
) (Decision, int, error) {
	capture := &responseCaptureWriter{ResponseWriter: w}
	rcode, err := plugin.NextOrFailure(b.Name(), b.Next, ctx, capture, r)
	if err != nil {
		return Decision{}, rcode, err
	}

	if capture.msg == nil && len(capture.raw) > 0 {
		msg := new(dns.Msg)
		if unpackErr := msg.Unpack(capture.raw); unpackErr == nil {
			capture.msg = msg
		}
	}

	if capture.msg != nil {
		if d, blocked := b.evaluateDeepChecks(engine, capture.msg.Answer, qtype); blocked {
			return d, 0, nil
		}

		if err := w.WriteMsg(capture.msg); err != nil {
			return Decision{}, dns.RcodeServerFailure, err
		}
		return Decision{Action: actionAllow, Code: codePass, Reason: "passthrough"}, capture.msg.Rcode, nil
	}

	if len(capture.raw) > 0 {
		if _, err := w.Write(capture.raw); err != nil {
			return Decision{}, dns.RcodeServerFailure, err
		}
	}

	return Decision{Action: actionAllow, Code: codePass, Reason: "passthrough"}, rcode, nil
}

func (b *BlockPolicy) evaluateDeepChecks(engine *Engine, answers []dns.RR, qtype QueryType) (Decision, bool) {
	var (
		deepCNAMEDuration  time.Duration
		responseIPDuration time.Duration
	)
	defer func() {
		if b.deepCNAME {
			matchDuration.WithLabelValues("deep_cname").Observe(deepCNAMEDuration.Seconds())
		}
		if b.responseIP {
			matchDuration.WithLabelValues("response_ip").Observe(responseIPDuration.Seconds())
		}
	}()

	for _, rr := range answers {
		if b.deepCNAME {
			decision, blocked, elapsed := evaluateCNAMECheck(engine, rr, qtype)
			deepCNAMEDuration += elapsed
			if blocked {
				return decision, true
			}
		}

		if b.responseIP {
			decision, blocked, elapsed := evaluateResponseIPCheck(engine, rr, qtype)
			responseIPDuration += elapsed
			if blocked {
				return decision, true
			}
		}
	}

	return Decision{}, false
}

func evaluateCNAMECheck(engine *Engine, rr dns.RR, qtype QueryType) (Decision, bool, time.Duration) {
	cname, ok := rr.(*dns.CNAME)
	if !ok {
		return Decision{}, false, 0
	}

	start := time.Now()
	target := normalizeQueryName(cname.Target)
	if target == "" {
		return Decision{}, false, 0
	}
	if engine.allow.matches(target) {
		return Decision{}, false, time.Since(start)
	}
	if engine.deny.matches(target) {
		return engine.blockDecision("cname", qtype), true, time.Since(start)
	}
	return Decision{}, false, time.Since(start)
}

func evaluateResponseIPCheck(engine *Engine, rr dns.RR, qtype QueryType) (Decision, bool, time.Duration) {
	var ip string
	switch v := rr.(type) {
	case *dns.A:
		ip = v.A.String()
	case *dns.AAAA:
		ip = v.AAAA.String()
	default:
		return Decision{}, false, 0
	}

	start := time.Now()
	if engine.allow.matchesIP(ip) {
		return Decision{}, false, time.Since(start)
	}
	if engine.deny.matchesIP(ip) {
		return engine.blockDecision("response_ip", qtype), true, time.Since(start)
	}
	return Decision{}, false, time.Since(start)
}

func (b *BlockPolicy) currentEngine() *Engine {
	engine := b.engine.Load()
	if engine == nil {
		return NewEngine(b.mode, nil, nil)
	}
	return engine
}

func (b *BlockPolicy) refreshLoop() {
	ticker := time.NewTicker(b.refreshPeriod)
	defer ticker.Stop()
	defer close(b.doneCh)

	for {
		select {
		case <-ticker.C:
			b.refreshOnce()
		case <-b.stopCh:
			return
		}
	}
}

func (b *BlockPolicy) refreshOnce() {
	if b.loader == nil {
		return
	}

	allow, deny, err := b.loader.load(context.Background())
	if err != nil {
		b.consecutiveRefreshErrors.Add(1)
		refreshTotal.WithLabelValues(b.policyName, "error").Inc()
		errorsTotal.WithLabelValues("refresh", "load").Inc()
		log.Errorf("list refresh failed for policy %q: %v", b.policyName, err)
		return
	}

	b.consecutiveRefreshErrors.Store(0)
	b.engine.Store(NewEngineWithMatchers(b.mode, allow, deny))
	refreshTotal.WithLabelValues(b.policyName, "success").Inc()
	refreshTimestamp.WithLabelValues(b.policyName).Set(float64(time.Now().Unix()))
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

func labelValues(ctx context.Context, policy, zone string, w dns.ResponseWriter) metricLabels {
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

type responseCaptureWriter struct {
	dns.ResponseWriter
	msg *dns.Msg
	raw []byte
}

func (w *responseCaptureWriter) WriteMsg(m *dns.Msg) error {
	if m == nil {
		log.Warningf("downstream plugin wrote nil DNS message")
		w.msg = nil
		return nil
	}
	w.msg = m.Copy()
	return nil
}

func (w *responseCaptureWriter) Write(b []byte) (int, error) {
	w.raw = append(w.raw, b...)
	return len(b), nil
}

var _ dns.ResponseWriter = (*responseCaptureWriter)(nil)
