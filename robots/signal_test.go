package robots

import (
	"slices"
	"strings"
	"testing"
)

func TestContentSignalManagedForm(t *testing.T) {
	// The form Cloudflare's managed robots.txt publishes: search granted,
	// training refused, and nothing said about ai-input.
	const input = `User-Agent: *
Content-Signal: search=yes, ai-train=no
Allow: /
`
	f := parse(t, input)
	if len(f.Findings) != 0 {
		t.Errorf("Content Signals Policy: a well-formed line should yield no findings, got %+v", f.Findings)
	}
	g, ok := f.Select("examplebot")
	if !ok {
		t.Fatal("the * group should govern a crawler the file does not name")
	}
	if want := (ContentSignal{Search: SignalYes, AITrain: SignalNo}); g.Signals != want {
		t.Errorf("Content Signals Policy: signals = %+v, want %+v", g.Signals, want)
	}
	if g.Signals.AIInput != SignalUnset {
		t.Errorf("Content Signals Policy: ai-input = %v, want %v: a key the line never gave is never a refusal", g.Signals.AIInput, SignalUnset)
	}
}

func TestContentSignalGrantsNothingAndRefusesNothing(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"no content-signal line", "User-agent: *\nDisallow: /a\n"},
		{"a blank content-signal line", "User-agent: *\nContent-Signal:\nDisallow: /a\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := parse(t, c.input)
			if len(f.Findings) != 0 {
				t.Errorf("findings = %+v, want none: declaring nothing is not a malformed line", f.Findings)
			}
			g, _ := f.Select("examplebot")
			for _, key := range SignalKeys {
				if got := g.Signals.Key(key); got != SignalUnset {
					t.Errorf("Content Signals Policy: %s = %v, want %v", key, got, SignalUnset)
				}
			}
		})
	}
}

func TestContentSignalScopedToItsGroup(t *testing.T) {
	const input = `User-agent: TrainBot
Content-Signal: ai-train=no
Disallow: /x

User-agent: *
Content-Signal: search=yes, ai-input=no
Disallow: /y
`
	f := parse(t, input)
	if len(f.Findings) != 0 {
		t.Errorf("findings = %+v, want none", f.Findings)
	}
	if train, _ := f.Select("trainbot"); train.Signals != (ContentSignal{AITrain: SignalNo}) {
		t.Errorf("signals of the named group = %+v, want only ai-train refused", train.Signals)
	}
	star, _ := f.Select("otherbot")
	if want := (ContentSignal{Search: SignalYes, AIInput: SignalNo}); star.Signals != want {
		t.Errorf("signals of the * group = %+v, want %+v", star.Signals, want)
	}
}

func TestContentSignalIgnoresUnknownKeysAndValues(t *testing.T) {
	const input = `User-agent: *
Content-Signal: search=yes, ai-summary=no
Content-Signal: ai-train=maybe, ai-input
`
	f := parse(t, input)

	if g, _ := f.Select("examplebot"); g.Signals != (ContentSignal{Search: SignalYes}) {
		t.Errorf("signals = %+v, want search granted and every ignored key unset", g.Signals)
	}

	want := []struct {
		kind  string
		line  int
		value string
	}{
		{FindingUnknownSignalKey, 2, "ai-summary=no"},
		{FindingMalformedSignal, 3, "ai-train=maybe"},
		{FindingMalformedSignal, 3, "ai-input"},
	}
	if len(f.Findings) != len(want) {
		t.Fatalf("findings = %+v, want %d of them", f.Findings, len(want))
	}
	for i, w := range want {
		got := f.Findings[i]
		if got.Kind != w.kind || got.Line != w.line || got.Value != w.value || got.Message == "" {
			t.Errorf("finding %d = %+v, want kind %q on line %d for %q with a message", i, got, w.kind, w.line, w.value)
		}
	}
}

func TestContentSignalConflictResolvesToNo(t *testing.T) {
	const input = `User-agent: *
Content-Signal: ai-train=yes
Disallow: /a

User-agent: *
Content-Signal: ai-train=no
`
	f := parse(t, input)

	if g, _ := f.Select("examplebot"); g.Signals.AITrain != SignalNo {
		t.Errorf("ai-train = %v, want %v: a key given twice with different values resolves to the value that restricts", g.Signals.AITrain, SignalNo)
	}
	if len(f.Findings) != 1 {
		t.Fatalf("findings = %+v, want one conflict", f.Findings)
	}
	got := f.Findings[0]
	if got.Kind != FindingSignalConflict || got.Value != "ai-train" {
		t.Fatalf("finding = %+v, want a %q finding about ai-train", got, FindingSignalConflict)
	}
	if !slices.Equal(got.Lines, []int{2, 6}) {
		t.Errorf("conflict lines = %v, want both lines [2 6]", got.Lines)
	}
	for _, line := range []string{"2", "6"} {
		if !strings.Contains(got.Message, line) {
			t.Errorf("conflict message = %q, want it to name line %s", got.Message, line)
		}
	}
}

func TestContentSignalRepeatedWithTheSameValue(t *testing.T) {
	const input = `User-agent: *
Content-Signal: search=yes
Content-Signal: search=yes
`
	f := parse(t, input)
	if len(f.Findings) != 0 {
		t.Errorf("findings = %+v, want none: a key repeated with the same value says nothing new", f.Findings)
	}
	if g, _ := f.Select("examplebot"); g.Signals.Search != SignalYes {
		t.Errorf("search = %v, want %v", g.Signals.Search, SignalYes)
	}
}

func TestContentSignalBeforeAnyUserAgent(t *testing.T) {
	const input = `Content-Signal: ai-train=no
User-agent: *
Disallow: /a
`
	f := parse(t, input)
	if g, _ := f.Select("examplebot"); g.Signals != (ContentSignal{}) {
		t.Errorf("signals = %+v, want every key unset: the line is dropped, not attached to the group that follows", g.Signals)
	}
	if len(f.Findings) != 1 || f.Findings[0].Kind != FindingRuleBeforeUserAgent || f.Findings[0].Line != 1 {
		t.Fatalf("findings = %+v, want one %q finding on line 1", f.Findings, FindingRuleBeforeUserAgent)
	}
}

func TestSignalString(t *testing.T) {
	cases := []struct {
		signal Signal
		want   string
	}{
		{SignalUnset, "unset"},
		{SignalYes, "yes"},
		{SignalNo, "no"},
	}
	for _, c := range cases {
		if got := c.signal.String(); got != c.want {
			t.Errorf("Signal(%d) = %q, want %q", c.signal, got, c.want)
		}
	}
}
