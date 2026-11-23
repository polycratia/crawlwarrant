// Package lint reads a robots.txt file against what crawler operators publish
// about the tokens it names and reports where the file contradicts itself: a
// finding names the token, the line that decided it, and the operator's own
// account of what refusing that token does.
package lint

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/polycratia/crawlwarrant/purpose"
	"github.com/polycratia/crawlwarrant/robots"
)

// DefaultPath is the path the rules are read for when Options names none.
const DefaultPath = "/"

// Severity says whether a finding contradicts the file itself or contradicts
// something the caller asked for.
type Severity uint8

const (
	// SeverityWarning is a contradiction to weigh: a site may well mean it.
	SeverityWarning Severity = iota + 1
	// SeverityError is a contradiction with something the caller asked for.
	SeverityError
)

func (s Severity) String() string {
	switch s {
	case SeverityWarning:
		return "warning"
	case SeverityError:
		return "error"
	}
	return "unset"
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(s.String())), nil
}

// Kinds of Finding.
const (
	// FindingAIInputSearchDisallowed reports a group that grants ai-input while
	// disallowing a search-index crawler: the content is given to the answer
	// and the link back is refused.
	FindingAIInputSearchDisallowed = "ai-input-granted-search-disallowed"
	// FindingSearchDisallowedTrainingAllowed reports an operator whose training
	// crawler is allowed while its search crawler is disallowed.
	FindingSearchDisallowedTrainingAllowed = "search-disallowed-training-allowed"
	// FindingControlTokenDisallowed reports a disallowed token no request is
	// ever sent under.
	FindingControlTokenDisallowed = "control-token-disallowed"
	// FindingRobotsMayNotApply reports a disallowed token whose operator
	// publishes that robots.txt may not apply to it.
	FindingRobotsMayNotApply = "robots-may-not-apply-disallowed"
	// FindingCitationWanted reports a disallowed search-index crawler for a
	// site that asked to be cited.
	FindingCitationWanted = "citation-wanted-search-disallowed"
)

// Finding is one thing the file says that its author probably did not mean.
type Finding struct {
	Kind     string   `json:"kind"`
	Severity Severity `json:"severity"`
	Token    string   `json:"token"`
	Operator string   `json:"operator"`
	Line     int      `json:"line"`
	Pattern  string   `json:"pattern"`
	Wording  string   `json:"wording"`
	Source   string   `json:"source"`
	Message  string   `json:"message"`
}

// Options is what a file is read against.
type Options struct {
	// Path is the path the rules are read for, DefaultPath when empty.
	Path string
	// WantCitation says the site wants to be cited in AI answers, which makes a
	// disallowed search-index crawler an error rather than a contradiction to
	// weigh.
	WantCitation bool
}

// decision is what the file does to one published token.
type decision struct {
	row        purpose.Row
	signals    robots.ContentSignal
	rule       robots.Rule
	disallowed bool
}

func decide(f robots.File, path string) []decision {
	out := make([]decision, 0, len(purpose.Table))
	for _, row := range purpose.Table {
		d := decision{row: row}
		group, _ := f.Select(row.Token)
		d.signals = group.Signals
		if rule, ok := group.Match(path); ok && rule.Kind == robots.Disallow {
			d.rule, d.disallowed = rule, true
		}
		out = append(out, d)
	}
	return out
}

func (d decision) finding(kind string, severity Severity, message string) Finding {
	return Finding{
		Kind:     kind,
		Severity: severity,
		Token:    d.row.Token,
		Operator: d.row.Operator,
		Line:     d.rule.Line,
		Pattern:  d.rule.Pattern,
		Wording:  d.row.Wording,
		Source:   d.row.SourceURL,
		Message:  message,
	}
}

// Check reads a parsed robots.txt file against the purpose table and returns
// what it found, in the order the checks run and the table lists its tokens.
func Check(f robots.File, opts Options) []Finding {
	path := opts.Path
	if path == "" {
		path = DefaultPath
	}
	ds := decide(f, path)

	var findings []Finding
	for _, d := range ds {
		if d.disallowed && d.row.Purpose == purpose.PurposeSearchIndex && d.signals.AIInput == robots.SignalYes {
			findings = append(findings, d.finding(FindingAIInputSearchDisallowed, SeverityWarning,
				fmt.Sprintf("ai-input=yes grants answering from the page, while disallow %q on line %d refuses %s, the crawler that builds the index those answers link back to",
					d.rule.Pattern, d.rule.Line, d.row.Token)))
		}
	}
	for _, d := range ds {
		if !d.disallowed || d.row.Purpose != purpose.PurposeSearchIndex {
			continue
		}
		for _, t := range ds {
			if t.disallowed || !t.row.Fetches || t.row.Operator != d.row.Operator || t.row.Purpose != purpose.PurposeTraining {
				continue
			}
			findings = append(findings, d.finding(FindingSearchDisallowedTrainingAllowed, SeverityWarning,
				fmt.Sprintf("%s is allowed to collect pages for training, while disallow %q on line %d refuses %s, the search index of the same operator",
					t.row.Token, d.rule.Pattern, d.rule.Line, d.row.Token)))
		}
	}
	for _, d := range ds {
		if d.disallowed && !d.row.Fetches {
			findings = append(findings, d.finding(FindingControlTokenDisallowed, SeverityWarning,
				fmt.Sprintf("disallow %q on line %d names %s, a token no request is ever sent under",
					d.rule.Pattern, d.rule.Line, d.row.Token)))
		}
	}
	for _, d := range ds {
		if d.disallowed && d.row.RobotsApplies == purpose.RobotsMayNot {
			findings = append(findings, d.finding(FindingRobotsMayNotApply, SeverityWarning,
				fmt.Sprintf("disallow %q on line %d refuses %s, whose operator publishes that robots.txt may not apply to it",
					d.rule.Pattern, d.rule.Line, d.row.Token)))
		}
	}
	if opts.WantCitation {
		for _, d := range ds {
			if d.disallowed && d.row.Purpose == purpose.PurposeSearchIndex {
				findings = append(findings, d.finding(FindingCitationWanted, SeverityError,
					fmt.Sprintf("the site asks to be cited, and disallow %q on line %d refuses %s, a search-index crawler",
						d.rule.Pattern, d.rule.Line, d.row.Token)))
			}
		}
	}
	return findings
}

// Count returns how many findings are errors and how many are warnings.
func Count(findings []Finding) (errors, warnings int) {
	for _, f := range findings {
		switch f.Severity {
		case SeverityError:
			errors++
		case SeverityWarning:
			warnings++
		}
	}
	return errors, warnings
}

// Summary is one line counting what was found.
func Summary(findings []Finding) string {
	if len(findings) == 0 {
		return "no findings"
	}
	errors, warnings := Count(findings)
	return fmt.Sprintf("%s, %s", plural(errors, "error"), plural(warnings, "warning"))
}

// Text renders findings for a terminal: the severity, the kind and the token,
// then the message, then the operator's wording with the document it was read
// from, and a closing summary line.
func Text(findings []Finding) string {
	var b strings.Builder
	for _, f := range findings {
		fmt.Fprintf(&b, "%s %s %s\n", f.Severity, f.Kind, f.Token)
		fmt.Fprintf(&b, "  %s\n", f.Message)
		if f.Wording != "" {
			fmt.Fprintf(&b, "  %s: %s (%s)\n", f.Operator, f.Wording, f.Source)
		}
	}
	fmt.Fprintf(&b, "%s\n", Summary(findings))
	return b.String()
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
