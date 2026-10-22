package robots

import "testing"

func TestMatchPathPattern(t *testing.T) {
	cases := []struct {
		section string
		pattern string
		match   []string
		noMatch []string
	}{
		{
			section: "2.2.2 path pattern table: /",
			pattern: "/",
			match:   []string{"/", "/fish", "/folder/page.html?id=1"},
		},
		{
			section: "2.2.2 path pattern table: /* is equivalent to /",
			pattern: "/*",
			match:   []string{"/", "/fish", "/folder/page.html?id=1"},
		},
		{
			section: "2.2.2 path pattern table: /fish",
			pattern: "/fish",
			match: []string{
				"/fish",
				"/fish.html",
				"/fish/salmon.html",
				"/fishheads",
				"/fishheads/yummy.html",
				"/fish.html?id=anything",
			},
			noMatch: []string{"/Fish.asp", "/catfish", "/?id=fish", "/desert/fish"},
		},
		{
			section: "2.2.2 path pattern table: /fish* matches like /fish",
			pattern: "/fish*",
			match:   []string{"/fish", "/fish.html", "/fishheads/yummy.html"},
			noMatch: []string{"/Fish.asp", "/catfish", "/desert/fish"},
		},
		{
			section: "2.2.2 path pattern table: /fish/",
			pattern: "/fish/",
			match:   []string{"/fish/", "/fish/?id=anything", "/fish/salmon.htm"},
			noMatch: []string{"/fish", "/fish.html", "/Fish/Salmon.asp"},
		},
		{
			section: "2.2.2 path pattern table: /*.php",
			pattern: "/*.php",
			match: []string{
				"/index.php",
				"/folder/filename.php",
				"/folder/filename.php?parameters",
				"/folder/any.php.file.html",
				"/filename.php/",
			},
			noMatch: []string{"/", "/windows.PHP"},
		},
		{
			section: "2.2.2 path pattern table: /*.php$",
			pattern: "/*.php$",
			match:   []string{"/filename.php", "/folder/filename.php"},
			noMatch: []string{"/filename.php?parameters", "/filename.php/", "/filename.php5", "/windows.PHP"},
		},
		{
			section: "2.2.2 path pattern table: /fish*.php",
			pattern: "/fish*.php",
			match:   []string{"/fish.php", "/fishheads/catfish.php?parameters"},
			noMatch: []string{"/Fish.PHP"},
		},
	}

	for _, c := range cases {
		t.Run(c.pattern, func(t *testing.T) {
			g := Group{Rules: []Rule{{Kind: Disallow, Pattern: c.pattern, Line: 1}}}
			for _, path := range c.match {
				if _, ok := g.Match(path); !ok {
					t.Errorf("RFC 9309 Section %s: %q should match %q", c.section, c.pattern, path)
				}
			}
			for _, path := range c.noMatch {
				if rule, ok := g.Match(path); ok {
					t.Errorf("RFC 9309 Section %s: %q should not match %q, got %+v", c.section, c.pattern, path, rule)
				}
			}
		})
	}
}

func TestMatchDecidingRule(t *testing.T) {
	cases := []struct {
		section  string
		name     string
		rules    []Rule
		path     string
		wantKind Kind
		wantLine int // 0 when no rule decides
	}{
		{
			section:  "2.2.2 the most specific match wins",
			name:     "longer disallow beats shorter allow",
			rules:    []Rule{{Kind: Allow, Pattern: "/folder", Line: 1}, {Kind: Disallow, Pattern: "/folder/page", Line: 2}},
			path:     "/folder/page",
			wantKind: Disallow,
			wantLine: 2,
		},
		{
			section:  "2.2.2 the most specific match wins",
			name:     "longer allow beats shorter disallow",
			rules:    []Rule{{Kind: Disallow, Pattern: "/folder", Line: 1}, {Kind: Allow, Pattern: "/folder/page", Line: 2}},
			path:     "/folder/page.html",
			wantKind: Allow,
			wantLine: 2,
		},
		{
			section:  "2.2.2 allow wins a tie with an equal disallow",
			name:     "allow listed first",
			rules:    []Rule{{Kind: Allow, Pattern: "/x", Line: 1}, {Kind: Disallow, Pattern: "/x", Line: 2}},
			path:     "/x/page",
			wantKind: Allow,
			wantLine: 1,
		},
		{
			section:  "2.2.2 allow wins a tie with an equal disallow",
			name:     "disallow listed first",
			rules:    []Rule{{Kind: Disallow, Pattern: "/x", Line: 1}, {Kind: Allow, Pattern: "/x", Line: 2}},
			path:     "/x/page",
			wantKind: Allow,
			wantLine: 2,
		},
		{
			section: "2.2.2 a path with no matching rule is allowed",
			name:    "no rule matches",
			rules:   []Rule{{Kind: Disallow, Pattern: "/private", Line: 1}},
			path:    "/public",
		},
		{
			section: "2.2.2 an empty disallow value matches nothing",
			name:    "empty disallow value",
			rules:   []Rule{{Kind: Disallow, Pattern: "", Line: 1}},
			path:    "/anything",
		},
		{
			section: "2.2.2 /robots.txt is always allowed",
			name:    "everything disallowed",
			rules:   []Rule{{Kind: Disallow, Pattern: "/", Line: 1}},
			path:    "/robots.txt",
		},
		{
			section:  "2.2.3 a trailing $ anchors the end of the match",
			name:     "anchored allow covers the exact end",
			rules:    []Rule{{Kind: Disallow, Pattern: "/*.php", Line: 1}, {Kind: Allow, Pattern: "/*.php$", Line: 2}},
			path:     "/index.php",
			wantKind: Allow,
			wantLine: 2,
		},
		{
			section:  "2.2.3 a trailing $ anchors the end of the match",
			name:     "anchored allow stops at a query string",
			rules:    []Rule{{Kind: Disallow, Pattern: "/*.php", Line: 1}, {Kind: Allow, Pattern: "/*.php$", Line: 2}},
			path:     "/index.php?id=1",
			wantKind: Disallow,
			wantLine: 1,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rule, ok := Group{Rules: c.rules}.Match(c.path)
			if c.wantLine == 0 {
				if ok {
					t.Fatalf("RFC 9309 Section %s: %q should have no deciding rule, got %+v", c.section, c.path, rule)
				}
				return
			}
			if !ok {
				t.Fatalf("RFC 9309 Section %s: %q should be decided by line %d, got none", c.section, c.path, c.wantLine)
			}
			if rule.Kind != c.wantKind || rule.Line != c.wantLine {
				t.Errorf("RFC 9309 Section %s: %q decided by %v line %d, want %v line %d", c.section, c.path, rule.Kind, rule.Line, c.wantKind, c.wantLine)
			}
		})
	}
}

func TestMatchPercentEncoding(t *testing.T) {
	cases := []struct {
		section string
		pattern string
		path    string
		want    bool
	}{
		{"2.2.2 octets are compared percent-encoded", "/caf%C3%A9", "/café", true},
		{"2.2.2 octets are compared percent-encoded", "/café", "/caf%C3%A9", true},
		{"2.2.2 unreserved characters are compared decoded", "/%7Euser/", "/~user/", true},
		{"2.2.2 unreserved characters are compared decoded", "/~user/", "/%7euser/", true},
		{"2.2.2 other escapes are compared uppercased", "/a%2Fb", "/a%2fb", true},
		{"2.2.2 a reserved escape is not the character it encodes", "/a%2Fb", "/a/b", false},
	}

	for _, c := range cases {
		g := Group{Rules: []Rule{{Kind: Disallow, Pattern: c.pattern, Line: 1}}}
		if _, ok := g.Match(c.path); ok != c.want {
			t.Errorf("RFC 9309 Section %s: %q against %q = %v, want %v", c.section, c.pattern, c.path, ok, c.want)
		}
	}
}
