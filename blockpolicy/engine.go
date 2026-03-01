package blockpolicy

type decisionAction string

const (
	actionAllow decisionAction = "allow"
	actionBlock decisionAction = "block"
)

type QueryType int

const (
	queryTypeOther QueryType = iota
	queryTypeA
	queryTypeAAAA
)

type Decision struct {
	Action decisionAction
	Code   decisionCode
	IP     string
	Reason string
	Mode   blockMode
}

type decisionCode int

const (
	codePass decisionCode = iota
	codeNXDomain
	codeSyntheticIP
)

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

func (e *Engine) Evaluate(name string, qtype QueryType) Decision {
	n := normalizeQueryName(name)
	if _, ok := e.allow[n]; ok {
		return Decision{Action: actionAllow, Code: codePass, Reason: "allowlist"}
	}
	if _, ok := e.deny[n]; !ok {
		return Decision{Action: actionAllow, Code: codePass, Reason: "passthrough"}
	}

	if e.mode == modeNXDomain {
		return Decision{Action: actionBlock, Code: codeNXDomain, Reason: "denylist", Mode: modeNXDomain}
	}

	switch qtype {
	case queryTypeA:
		return Decision{Action: actionBlock, Code: codeSyntheticIP, IP: "0.0.0.0", Reason: "denylist", Mode: modeZeroIP}
	case queryTypeAAAA:
		return Decision{Action: actionBlock, Code: codeSyntheticIP, IP: "::", Reason: "denylist", Mode: modeZeroIP}
	default:
		return Decision{Action: actionBlock, Code: codeNXDomain, Reason: "denylist", Mode: modeZeroIP}
	}
}
