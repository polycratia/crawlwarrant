package robots

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestFromFetchEffects(t *testing.T) {
	const body = "User-agent: *\nDisallow: /private\n"
	cases := []struct {
		section string
		name    string
		outcome Outcome
		want    Effect
	}{
		{"2.3.1.1 a successful fetch is parsed", "200", Outcome{Status: 200, Body: []byte(body)}, EffectRules},
		{"2.3.1.1 any 2xx is a successful fetch", "204", Outcome{Status: 204}, EffectRules},
		{"2.3.1.2 at least five consecutive redirects are followed", "five hops", Outcome{Status: 200, Redirects: 5, Body: []byte(body)}, EffectRules},
		{"2.3.1.2 more than five redirects make the file unavailable", "six hops", Outcome{Status: 200, Redirects: 6, Body: []byte(body)}, EffectAllowAll},
		{"2.3.1.2 a chain that reaches no file leaves it unavailable", "ends on a redirect", Outcome{Status: 301, Redirects: 1}, EffectAllowAll},
		{"2.3.1.3 an unavailable status allows every path", "404", Outcome{Status: 404}, EffectAllowAll},
		{"2.3.1.3 an unavailable status allows every path", "403", Outcome{Status: 403}, EffectAllowAll},
		{"2.3.1.3 an unavailable status allows every path", "400", Outcome{Status: 400}, EffectAllowAll},
		{"2.3.1.4 an unreachable file is a complete disallow", "500", Outcome{Status: 500}, EffectDisallowAll},
		{"2.3.1.4 an unreachable file is a complete disallow", "503", Outcome{Status: 503}, EffectDisallowAll},
		{"2.3.1.4 a network error is unreachable", "transport error", Outcome{Err: errors.New("dial tcp: i/o timeout")}, EffectDisallowAll},
		{"2.3.1.4 a fetch with no response is unreachable", "no status", Outcome{}, EffectDisallowAll},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := FromFetch(c.outcome)
			if p.Effect != c.want {
				t.Errorf("RFC 9309 Section %s: effect of %+v = %v, want %v", c.section, c.outcome, p.Effect, c.want)
			}
			if p.Divergence != nil {
				t.Errorf("RFC 9309 Section %s: %+v should decide on its own, got divergence %+v", c.section, c.outcome, p.Divergence)
			}
			if p.Reason == "" || p.Source.URL == "" {
				t.Errorf("RFC 9309 Section %s: policy = %+v, want a reason and a source URL", c.section, p)
			}
		})
	}
}

func TestFromFetchParsesSuccessfulBody(t *testing.T) {
	p := FromFetch(Outcome{Status: 200, Body: []byte("User-agent: *\nDisallow: /private\n")})
	g, ok := p.File.Select("examplebot")
	if !ok || g.Token != "*" {
		t.Fatalf("RFC 9309 Section 2.3.1.1: selected group = %+v (ok %v), want the * group of the fetched body", g, ok)
	}
	rule, ok := g.Match("/private/page")
	if !ok || rule.Kind != Disallow {
		t.Errorf("RFC 9309 Section 2.3.1.1: /private/page decided by %+v (ok %v), want a disallow from the body", rule, ok)
	}
	if rule, ok := g.Match("/public"); ok {
		t.Errorf("RFC 9309 Section 2.3.1.1: /public should have no deciding rule, got %+v", rule)
	}
}

func TestFromFetchUnreachableReportsTheStatus(t *testing.T) {
	p := FromFetch(Outcome{Status: 503})
	if !strings.Contains(p.Reason, "503") || !strings.Contains(p.Reason, "currently disallowing everything") {
		t.Errorf("RFC 9309 Section 2.3.1.4: reason = %q, want the status and %q", p.Reason, "currently disallowing everything")
	}
}

func TestFromFetchTooManyRequestsIsDivergent(t *testing.T) {
	p := FromFetch(Outcome{Status: 429})
	if p.Effect != EffectUndecided {
		t.Errorf("status 429 effect = %v, want %v until a reading is picked", p.Effect, EffectUndecided)
	}
	if p.Divergence == nil || p.Divergence.Status != 429 || len(p.Divergence.Interpretations) != 2 {
		t.Fatalf("divergence = %+v, want both readings of status 429", p.Divergence)
	}
	for _, i := range p.Divergence.Interpretations {
		if i.Source.URL == "" || i.Reason == "" {
			t.Errorf("interpretation %+v, want a source URL and a reason", i)
		}
	}

	cases := []struct {
		reading Reading
		want    Effect
	}{
		{ReadingRFC9309, EffectAllowAll},
		{ReadingGoogle, EffectDisallowAll},
	}
	for _, c := range cases {
		got, err := p.Under(c.reading)
		if err != nil {
			t.Fatalf("Under(%v): %v", c.reading, err)
		}
		if got.Effect != c.want {
			t.Errorf("Under(%v) effect = %v, want %v", c.reading, got.Effect, c.want)
		}
		if got.Status != 429 || got.Divergence == nil || got.Source.URL == "" || got.Reason == "" {
			t.Errorf("Under(%v) = %+v, want the status, the divergence and the chosen source kept", c.reading, got)
		}
	}

	if _, err := p.Under(Reading(0)); !errors.Is(err, ErrReadingRequired) {
		t.Errorf("Under(zero reading) error = %v, want %v: a divergent status has no default reading", err, ErrReadingRequired)
	}
	if _, err := p.Under(Reading(99)); !errors.Is(err, ErrReadingRequired) {
		t.Errorf("Under(unknown reading) error = %v, want %v", err, ErrReadingRequired)
	}
}

func TestUnderLeavesASettledPolicyAlone(t *testing.T) {
	p := FromFetch(Outcome{Status: 404})
	got, err := p.Under(Reading(0))
	if err != nil {
		t.Fatalf("Under: %v", err)
	}
	if got.Effect != p.Effect || got.Reason != p.Reason || got.Source != p.Source {
		t.Errorf("Under on a settled policy = %+v, want %+v unchanged", got, p)
	}
}

func TestFreshnessTable(t *testing.T) {
	if len(FreshFor) == 0 {
		t.Fatal("FreshFor is empty, want the published caching limits")
	}
	for _, f := range FreshFor {
		if f.Limit != 24*time.Hour {
			t.Errorf("RFC 9309 Section 2.4: row %+v, want a 24 hour limit", f)
		}
		if f.Source.URL == "" || f.Note == "" {
			t.Errorf("row %+v, want a source URL and a note", f)
		}
	}
}

func TestUnreachabilityTable(t *testing.T) {
	var rfc, google []Unreachability
	for _, u := range WhileUnreachable {
		if u.Source.URL == "" || u.Note == "" || u.Effect == EffectUndecided {
			t.Errorf("row %+v, want a source URL, a note and an effect", u)
		}
		switch u.Source {
		case sourceUnreachable:
			rfc = append(rfc, u)
		case sourceGoogleCodes:
			google = append(google, u)
		}
	}

	afters := func(rows []Unreachability) []time.Duration {
		var out []time.Duration
		for _, r := range rows {
			out = append(out, r.After)
		}
		return out
	}
	const day = 24 * time.Hour

	if want := []time.Duration{0, 30 * day}; !slices.Equal(afters(rfc), want) {
		t.Fatalf("RFC 9309 Section 2.3.1.4: rows at %v, want %v", afters(rfc), want)
	}
	if rfc[0].Effect != EffectDisallowAll || rfc[1].Effect != EffectAllowAll {
		t.Errorf("RFC 9309 Section 2.3.1.4: effects %v then %v, want a complete disallow that may become unavailable after 30 days", rfc[0].Effect, rfc[1].Effect)
	}

	if want := []time.Duration{0, 12 * time.Hour, 30 * day}; !slices.Equal(afters(google), want) {
		t.Fatalf("Google result codes: rows at %v, want %v", afters(google), want)
	}
	if google[0].Effect != EffectDisallowAll || google[1].Effect != EffectRules || google[2].Effect != EffectAllowAll {
		t.Errorf("Google result codes: effects %v, %v, %v, want disallow all, then a cached file, then allow all", google[0].Effect, google[1].Effect, google[2].Effect)
	}
}
