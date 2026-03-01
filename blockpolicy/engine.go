package blockpolicy

type decisionAction string

const (
	actionAllow decisionAction = "allow"
	actionBlock decisionAction = "block"
)

const (
	rcodeSuccess  = 0
	rcodeNXDomain = 3
	qtypeA        = 1
	qtypeAAAA     = 28
)

type Decision struct {
	Action decisionAction
	RCode  int
	IP     string
}

type Engine struct {
	mode  blockMode
	allow map[string]struct{}
	deny  map[string]struct{}
}

func NewEngine(mode blockMode, allow, deny map[string]struct{}) *Engine {
	if allow == nil {
		allow = map[string]struct{}{}
	}
	if deny == nil {
		deny = map[string]struct{}{}
	}
	return &Engine{
		mode:  mode,
		allow: allow,
		deny:  deny,
	}
}

func (e *Engine) Evaluate(name string, qtype uint16) Decision {
	n := normalizeName(name)
	if _, ok := e.allow[n]; ok {
		return Decision{Action: actionAllow, RCode: rcodeSuccess}
	}
	if _, ok := e.deny[n]; !ok {
		return Decision{Action: actionAllow, RCode: rcodeSuccess}
	}

	if e.mode == modeNXDomain {
		return Decision{Action: actionBlock, RCode: rcodeNXDomain}
	}

	switch qtype {
	case qtypeA:
		return Decision{Action: actionBlock, RCode: rcodeSuccess, IP: "0.0.0.0"}
	case qtypeAAAA:
		return Decision{Action: actionBlock, RCode: rcodeSuccess, IP: "::"}
	default:
		return Decision{Action: actionBlock, RCode: rcodeNXDomain}
	}
}
