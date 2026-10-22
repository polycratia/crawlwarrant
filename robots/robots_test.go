package robots

import (
	"reflect"
	"strings"
	"testing"
)

func parse(t *testing.T, input string) File {
	t.Helper()
	f, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return f
}

func TestParseMergesGroupsByToken(t *testing.T) {
	const input = `# a comment line
User-Agent: ExampleBot
Disallow: /private   # a trailing comment
Allow: /private/public

User-agent: *
Disallow: /tmp

user-agent: examplebot
user-agent: Other-Bot
Disallow:
Sitemap: https://example.com/sitemap.xml
Disallow: /late
`
	want := []Group{
		{Token: "examplebot", Rules: []Rule{
			{Kind: Disallow, Pattern: "/private", Line: 3},
			{Kind: Allow, Pattern: "/private/public", Line: 4},
			{Kind: Disallow, Pattern: "", Line: 11},
			{Kind: Disallow, Pattern: "/late", Line: 13},
		}},
		{Token: "*", Rules: []Rule{
			{Kind: Disallow, Pattern: "/tmp", Line: 7},
		}},
		{Token: "other-bot", Rules: []Rule{
			{Kind: Disallow, Pattern: "", Line: 11},
			{Kind: Disallow, Pattern: "/late", Line: 13},
		}},
	}

	f := parse(t, input)
	if len(f.Findings) != 0 {
		t.Errorf("RFC 9309 Section 2.2.1: a well-formed file should yield no findings, got %+v", f.Findings)
	}
	if !reflect.DeepEqual(f.Groups, want) {
		t.Errorf("RFC 9309 Sections 2.1 and 2.2.1: groups = %+v, want %+v", f.Groups, want)
	}
}

func TestSelect(t *testing.T) {
	const withStar = `User-agent: ExampleBot
Disallow: /a

User-agent: *
Disallow: /b
`
	f := parse(t, withStar)

	cases := []struct {
		section string
		name    string
		token   string
		want    string
	}{
		{"2.2.1 the group naming the product token governs", "exact token", "examplebot", "examplebot"},
		{"2.2.1 product tokens match case-insensitively", "mixed case", "ExAmPlEbOt", "examplebot"},
		{"2.2.1 an unmatched crawler obeys the * group", "fallback", "unknownbot", "*"},
		{"2.2.1 the * group can be asked for by name", "star", "*", "*"},
		{"2.2.1 a token is never matched as a substring", "substring of a known token", "bot", "*"},
		{"2.2.1 a token is never matched as a substring", "known token as a substring", "myexamplebot", "*"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g, ok := f.Select(c.token)
			if !ok {
				t.Fatalf("RFC 9309 Section %s: Select(%q) found no group, want %q", c.section, c.token, c.want)
			}
			if g.Token != c.want {
				t.Errorf("RFC 9309 Section %s: Select(%q) = %q, want %q", c.section, c.token, g.Token, c.want)
			}
		})
	}

	const noStar = `User-agent: ExampleBot
Disallow: /a
`
	g, ok := parse(t, noStar).Select("unknownbot")
	if ok {
		t.Errorf("RFC 9309 Section 2.2.1: a file with no * group should select nothing, got %+v", g)
	}
	if rule, ok := g.Match("/a"); ok {
		t.Errorf("RFC 9309 Section 2.2.1: an unselected crawler should be allowed everywhere, got %+v", rule)
	}
}

func TestParseFindings(t *testing.T) {
	const input = `Disallow: /early
User-agent: Googlebot/1.2
Disallow: /a
User-agent: *bot*
Disallow: /b
`
	f := parse(t, input)

	want := []struct {
		kind  string
		line  int
		value string
	}{
		{FindingRuleBeforeUserAgent, 1, "/early"},
		{FindingTokenPrefix, 2, "Googlebot/1.2"},
		{FindingNonPortableToken, 4, "*bot*"},
	}
	if len(f.Findings) != len(want) {
		t.Fatalf("findings = %+v, want %d of them", f.Findings, len(want))
	}
	for i, w := range want {
		got := f.Findings[i]
		if got.Kind != w.kind || got.Line != w.line || got.Value != w.value || got.Message == "" {
			t.Errorf("finding %d = %+v, want kind %q on line %d for value %q with a message", i, got, w.kind, w.line, w.value)
		}
	}
	const wantMessage = "not an RFC 9309 product token, Google's parser matches nothing, other crawlers may match substrings"
	if got := f.Findings[2].Message; got != wantMessage {
		t.Errorf("non-portable token message = %q, want %q", got, wantMessage)
	}

	wantGroups := []Group{{Token: "googlebot", Rules: []Rule{{Kind: Disallow, Pattern: "/a", Line: 3}}}}
	if !reflect.DeepEqual(f.Groups, wantGroups) {
		t.Errorf("RFC 9309 Section 2.2.1: groups = %+v, want %+v", f.Groups, wantGroups)
	}
	if g, ok := f.Select("*bot*"); ok {
		t.Errorf("RFC 9309 Section 2.2.1: a value that is not a product token should name no group, got %+v", g)
	}
}

func TestParseTruncation(t *testing.T) {
	const head = "User-agent: *\n"
	const tail = "Disallow: /last\n"
	filler := func(n int) string { return strings.Repeat("#", n-1) + "\n" }

	t.Run("exactly at the boundary", func(t *testing.T) {
		input := head + filler(MaxBytes-len(head)-len(tail)) + tail
		if len(input) != MaxBytes {
			t.Fatalf("test input is %d bytes, want %d", len(input), MaxBytes)
		}
		f := parse(t, input)
		if len(f.Findings) != 0 {
			t.Errorf("RFC 9309 Section 2.5: %d bytes should not be truncated, got %+v", MaxBytes, f.Findings)
		}
		g, _ := f.Select("anybot")
		if len(g.Rules) != 1 || g.Rules[0].Pattern != "/last" {
			t.Errorf("RFC 9309 Section 2.5: the last rule within the limit should be kept, got %+v", g.Rules)
		}
	})

	t.Run("one line past the boundary", func(t *testing.T) {
		input := head + filler(MaxBytes-len(head)-len(tail)) + tail + "Disallow: /over\n"
		f := parse(t, input)
		if len(f.Findings) != 1 || f.Findings[0].Kind != FindingTruncated || f.Findings[0].Offset != MaxBytes {
			t.Fatalf("RFC 9309 Section 2.5: findings = %+v, want one %q finding at offset %d", f.Findings, FindingTruncated, MaxBytes)
		}
		g, _ := f.Select("anybot")
		if len(g.Rules) != 1 || g.Rules[0].Pattern != "/last" {
			t.Errorf("RFC 9309 Section 2.5: rules = %+v, want only the rule inside the limit", g.Rules)
		}
	})

	t.Run("a line cut by the boundary is dropped", func(t *testing.T) {
		input := head + filler(MaxBytes-len(head)-5) + tail
		f := parse(t, input)
		if len(f.Findings) != 1 || f.Findings[0].Kind != FindingTruncated || f.Findings[0].Offset != MaxBytes {
			t.Fatalf("RFC 9309 Section 2.5: findings = %+v, want one %q finding at offset %d", f.Findings, FindingTruncated, MaxBytes)
		}
		g, ok := f.Select("anybot")
		if !ok || g.Token != "*" {
			t.Fatalf("RFC 9309 Section 2.5: the groups inside the limit should survive, got %+v (ok %v)", g, ok)
		}
		if len(g.Rules) != 0 {
			t.Errorf("RFC 9309 Section 2.5: a rule cut by the limit should be dropped, got %+v", g.Rules)
		}
	})
}
