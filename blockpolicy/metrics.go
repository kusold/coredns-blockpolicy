//go:build coredns

package blockpolicy

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	registerMetricsOnce sync.Once
	queriesTotal        = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "coredns",
		Subsystem: "blockpolicy",
		Name:      "queries_total",
		Help:      "Total number of DNS queries evaluated by blockpolicy.",
	}, []string{"policy"})
	blockedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "coredns",
		Subsystem: "blockpolicy",
		Name:      "blocked_total",
		Help:      "Total number of blocked DNS queries.",
	}, []string{"policy", "mode", "reason"})
)

func registerMetrics() {
	registerMetricsOnce.Do(func() {
		prometheus.MustRegister(queriesTotal)
		prometheus.MustRegister(blockedTotal)
	})
}
