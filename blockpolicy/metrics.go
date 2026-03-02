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

	matchDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: "blockpolicy",
		Name:      "match_duration_seconds",
		Help:      "Time spent in matching phases.",
	}, []string{"phase"})

	listEntries = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "blockpolicy",
		Name:      "list_entries",
		Help:      "Number of list entries loaded by policy/group/kind.",
	}, []string{"policy", "group", "kind"})

	refreshTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "blockpolicy",
		Name:      "refresh_total",
		Help:      "Total number of list refresh attempts by result.",
	}, []string{"policy", "result"})

	refreshTimestamp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "blockpolicy",
		Name:      "refresh_timestamp_seconds",
		Help:      "Unix timestamp of the most recent successful refresh.",
	}, []string{"policy"})

	errorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "blockpolicy",
		Name:      "errors_total",
		Help:      "Total number of plugin errors by stage/type.",
	}, []string{"stage", "type"})
)

func init() {
	mustRegisterOrReuseCounterVec(&queriesTotal)
	mustRegisterOrReuseCounterVec(&blockedTotal)
	mustRegisterOrReuseCounterVec(&allowedTotal)
	mustRegisterOrReuseHistogramVec(&matchDuration)
	mustRegisterOrReuseGaugeVec(&listEntries)
	mustRegisterOrReuseCounterVec(&refreshTotal)
	mustRegisterOrReuseGaugeVec(&refreshTimestamp)
	mustRegisterOrReuseCounterVec(&errorsTotal)
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

func mustRegisterOrReuseGaugeVec(vec **prometheus.GaugeVec) {
	if err := prometheus.Register(*vec); err != nil {
		if already, ok := err.(prometheus.AlreadyRegisteredError); ok {
			existing, ok := already.ExistingCollector.(*prometheus.GaugeVec)
			if !ok {
				panic(fmt.Sprintf("blockpolicy metrics registration type mismatch: %T", already.ExistingCollector))
			}
			*vec = existing
			return
		}
		panic(err)
	}
}

func mustRegisterOrReuseHistogramVec(vec **prometheus.HistogramVec) {
	if err := prometheus.Register(*vec); err != nil {
		if already, ok := err.(prometheus.AlreadyRegisteredError); ok {
			existing, ok := already.ExistingCollector.(*prometheus.HistogramVec)
			if !ok {
				panic(fmt.Sprintf("blockpolicy metrics registration type mismatch: %T", already.ExistingCollector))
			}
			*vec = existing
			return
		}
		panic(err)
	}
}
