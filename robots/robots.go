// Package robots parses robots.txt files and reports which rule decides a
// path, following RFC 9309.
package robots

import (
	"bufio"
	"io"
	"strings"
)

// Kind distinguishes allow rules from disallow rules. The zero value means no
// rule at all, as in the Rule returned by Group.Match when nothing decides.
type Kind uint8

const (
	Allow Kind = iota + 1
	Disallow
)

func (k Kind) String() string {
	switch k {
	case Allow:
		return "allow"
	case Disallow:
		return "disallow"
	}
	return "none"
}

// Rule is one allow or disallow line of a robots.txt file.
type Rule struct {
	Kind    Kind
	Pattern string // value as written in the file, before normalization
	Line    int    // 1-based line number the rule was read from
}

// Group is a single robots.txt record: the product tokens it speaks to and the
// rules that follow them.
type Group struct {
	Agents []string // product tokens, lowercased, in file order
	Rules  []Rule
}

// Parse reads a robots.txt file and returns its groups in file order. Lines it
// cannot understand are skipped, and the only error reported is a read failure.
func Parse(r io.Reader) ([]Group, error) {
	var groups []Group
	current := -1
	startGroup := true

	sc := bufio.NewScanner(r)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if line == 1 {
			text = strings.TrimPrefix(text, "\ufeff")
		}
		if i := strings.IndexByte(text, '#'); i >= 0 {
			text = text[:i]
		}
		colon := strings.IndexByte(text, ':')
		if colon < 0 {
			continue
		}
		field := strings.ToLower(strings.TrimSpace(text[:colon]))
		value := strings.TrimSpace(text[colon+1:])

		switch field {
		case "user-agent":
			if startGroup {
				groups = append(groups, Group{})
				current = len(groups) - 1
				startGroup = false
			}
			groups[current].Agents = append(groups[current].Agents, strings.ToLower(value))
		case "allow", "disallow":
			if current < 0 {
				continue
			}
			kind := Allow
			if field == "disallow" {
				kind = Disallow
			}
			groups[current].Rules = append(groups[current].Rules, Rule{Kind: kind, Pattern: value, Line: line})
			startGroup = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return groups, nil
}
