package lint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/polycratia/crawlwarrant/purpose"
	"github.com/polycratia/crawlwarrant/robots"
)

const aiInputRobots = `User-agent: OAI-SearchBot
Content-Signal: ai-input=yes
Disallow: /
`

const controlTokenRobots = `User-agent: Google-Extended
Disallow: /
`

const mayNotApplyRobots = `User-agent: ChatGPT-User
Disallow: /
`

const citationRobots = `User-agent: Claude-SearchBot
Disallow: /

User-agent: PerplexityBot
Disallow: /
`

const cleanRobots = `User-agent: *
Disallow: /private
`

func check(t *testing.T, input string, opts Options) []Finding {
	t.Helper()
	f, err := robots.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("robots.Parse: %v", err)
	}
	return Check(f, opts)
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the golden file: %v", err)
	}
	if got != string(want) {
		t.Errorf("%s:\n--- got ---\n%s--- want ---\n%s", path, got, want)
	}
}

func TestGoldenFindings(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		opts   Options
		golden string
	}{
		{"ai-input granted while the search index is refused", aiInputRobots, Options{}, "ai_input.txt"},
		{"a token no request is sent under", controlTokenRobots, Options{}, "control_token.txt"},
		{"a fetch a person asked for", mayNotApplyRobots, Options{}, "robots_may_not.txt"},
		{"citations wanted from crawlers the file refuses", citationRobots, Options{WantCitation: true}, "want_citation.txt"},
		{"a file with nothing to report", cleanRobots, Options{}, "clean.txt"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			golden(t, c.golden, Text(check(t, c.input, c.opts)))
		})
	}
}

func TestWantCitationMakesADisallowedSearchCrawlerAnError(t *testing.T) {
	for _, f := range check(t, citationRobots, Options{}) {
		if f.Kind == FindingCitationWanted {
			t.Errorf("finding %+v, want none of its kind: nothing asked to be cited", f)
		}
		if f.Severity != SeverityWarning {
			t.Errorf("severity of %+v = %v, want %v", f, f.Severity, SeverityWarning)
		}
	}

	var errs []Finding
	for _, f := range check(t, citationRobots, Options{WantCitation: true}) {
		if f.Severity == SeverityError {
			errs = append(errs, f)
		}
	}
	if len(errs) != 2 {
		t.Fatalf("errors = %+v, want one for each disallowed search-index crawler", errs)
	}
	want := map[string]int{"Claude-SearchBot": 2, "PerplexityBot": 5}
	for _, f := range errs {
		if f.Kind != FindingCitationWanted {
			t.Errorf("kind = %q, want %q", f.Kind, FindingCitationWanted)
		}
		if line, ok := want[f.Token]; !ok || f.Line != line {
			t.Errorf("finding = %+v, want a known token on its own line", f)
		}
	}
}

func TestEveryFindingNamesTheTokenTheLineAndTheWording(t *testing.T) {
	inputs := []struct {
		input string
		opts  Options
	}{
		{aiInputRobots, Options{}},
		{controlTokenRobots, Options{}},
		{mayNotApplyRobots, Options{}},
		{citationRobots, Options{WantCitation: true}},
	}
	kinds := make(map[string]bool)
	for _, in := range inputs {
		findings := check(t, in.input, in.opts)
		if len(findings) == 0 {
			t.Errorf("no findings for:\n%s", in.input)
		}
		for _, f := range findings {
			kinds[f.Kind] = true
			if f.Token == "" || f.Line == 0 || f.Pattern == "" {
				t.Errorf("finding = %+v, want the token and the line the rule was read from", f)
			}
			if f.Wording == "" || f.Source == "" {
				t.Errorf("finding = %+v, want the vendor wording and the document it was read from", f)
			}
			if !strings.Contains(f.Message, f.Token) {
				t.Errorf("message = %q, want it to name %s", f.Message, f.Token)
			}
		}
	}
	for _, kind := range []string{
		FindingAIInputSearchDisallowed,
		FindingSearchDisallowedTrainingAllowed,
		FindingControlTokenDisallowed,
		FindingRobotsMayNotApply,
		FindingCitationWanted,
	} {
		if !kinds[kind] {
			t.Errorf("no fixture produced a %q finding", kind)
		}
	}
}

func TestPathDecidesWhichRuleIsRead(t *testing.T) {
	const input = `User-agent: OAI-SearchBot
Disallow: /articles/
`
	if findings := check(t, input, Options{}); len(findings) != 0 {
		t.Errorf("findings = %+v, want none: %q is not disallowed", findings, DefaultPath)
	}
	findings := check(t, input, Options{Path: "/articles/one"})
	if len(findings) != 1 || findings[0].Kind != FindingSearchDisallowedTrainingAllowed || findings[0].Line != 2 {
		t.Fatalf("findings = %+v, want the rule on line 2 read for the path given", findings)
	}
}

func TestEveryPublishedRowCarriesWording(t *testing.T) {
	for _, row := range purpose.Table {
		if row.Wording == "" {
			t.Errorf("%s: no Wording, so a finding about it has nothing of the operator's to quote", row.Token)
		}
	}
}
