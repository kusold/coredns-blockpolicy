package blockpolicy

import (
	"context"
	"strings"
	"testing"
	"time"
)

func FuzzParseEntriesWithBlocky(f *testing.F) {
	f.Add("auto", "ads.example\n0.0.0.0 tracker.example\n", true, true, true, true)
	f.Add("domain", "alpha.example\nbeta.example\n", true, true, false, true)
	f.Add("wildcard", "*.wild.example\n", true, true, true, true)
	f.Add("regex", "/^ads[0-9]+\\.example$/\n", true, true, true, true)
	f.Add("hosts", "127.0.0.1 host.example alias.example\n", true, true, true, true)

	f.Fuzz(func(t *testing.T, format, body string, exact, wildcard, regex, hosts bool) {
		if len(body) > 1<<16 {
			t.Skip()
		}

		format = strings.ToLower(strings.TrimSpace(format))
		if !isSupportedListFormat(format) {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		builder := newEntryBuilder()
		matching := MatchingConfig{
			Exact:           exact,
			Wildcard:        wildcard,
			Regex:           regex,
			HostsFormat:     hosts,
			DeepCNAME:       true,
			ResponseIPLists: true,
		}
		_ = parseEntriesWithBlocky(ctx, format, strings.NewReader(body), builder, matching, func(error) {})
		_ = builder.toMatcherSet()
	})
}

func FuzzEngineEvaluate(f *testing.F) {
	f.Add("ads.example\n", "allow.example\n", "ads.example.", uint8(0), uint8(0))
	f.Add("*.blocked.example\n", "/^allow[0-9]+\\.example$/\n", "allow42.example.", uint8(1), uint8(1))
	f.Add("/foo/\n10.0.0.1\n", "127.0.0.1\n", "foo.example.", uint8(2), uint8(0))

	f.Fuzz(func(t *testing.T, denyBody, allowBody, query string, qtype, mode uint8) {
		if len(denyBody) > 1<<16 || len(allowBody) > 1<<16 || len(query) > 512 {
			t.Skip()
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		allowBuilder := newEntryBuilder()
		denyBuilder := newEntryBuilder()
		matching := effectiveMatchingConfig(MatchingConfig{})

		_ = parseEntriesWithBlocky(ctx, "auto", strings.NewReader(allowBody), allowBuilder, matching, func(error) {})
		_ = parseEntriesWithBlocky(ctx, "auto", strings.NewReader(denyBody), denyBuilder, matching, func(error) {})

		engineMode := modeZeroIP
		if mode%2 == 1 {
			engineMode = modeNXDomain
		}
		engine := NewEngineWithMatchers(engineMode, allowBuilder.toMatcherSet(), denyBuilder.toMatcherSet())
		_ = engine.Evaluate(query, QueryType(qtype%3))
	})
}
