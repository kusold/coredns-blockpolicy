//go:build coredns

package blockpolicy

import (
	"fmt"

	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	queriesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "blockpolicy",
		Name:      "queries_total",
		Help:      "Total number of DNS queries evaluated by blockpolicy.",
	}, []string{"server", "zone", "view", "policy", "qtype"})

	blockedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "blockpolicy",
		Name:      "blocked_total",
		Help:      "Total number of blocked DNS queries.",
	}, []string{"server", "zone", "view", "policy", "reason", "mode", "rcode"})

	allowedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "blockpolicy",
		Name:      "allowed_total",
		Help:      "Total number of allowed DNS queries.",
	}, []string{"server", "zone", "view", "policy", "reason"})
)

func init() {
	mustRegisterOrReuseCounterVec(&queriesTotal)
	mustRegisterOrReuseCounterVec(&blockedTotal)
	mustRegisterOrReuseCounterVec(&allowedTotal)
}

func mustRegisterOrReuseCounterVec(vec **prometheus.CounterVec) {
	if err := prometheus.Register(*vec); err != nil {
		if already, ok := err.(prometheus.AlreadyRegisteredError); ok {
			existing, ok := already.ExistingCollector.(*prometheus.CounterVec)
			if !ok {
				panic(fmt.Sprintf("blockpolicy metrics registration type mismatch: %T", already.ExistingCollector))
			}
			*vec = existing
			return
		}
		panic(err)
	}
}
