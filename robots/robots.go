// Package robots parses robots.txt files and reports which rule decides a
// path, following RFC 9309.
package robots

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"strings"
)

// MaxBytes is the most input Parse reads. RFC 9309, Section 2.5, lets a
// crawler stop after 500 KiB; the bytes past that offset are ignored and
// reported as a Finding of Kind FindingTruncated.
const MaxBytes = 500 << 10

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

// Group holds the rules that govern one product token. Per RFC 9309, Section
// 2.2.1, the rules of every group in the file that names the token are merged
// here, in file order.
type Group struct {
	Token string // product token, lowercased, or "*" for the default group
	Rules []Rule
}

// Kinds of Finding.
const (
	// FindingNonPortableToken reports a user-agent value that does not start
	// with a product token, such as "*bot*". It names no group.
	FindingNonPortableToken = "non-portable-token"
	// FindingTokenPrefix reports a user-agent value that starts with a product
	// token and continues with other characters, such as "googlebot/1.2". The
	// prefix names the group.
	FindingTokenPrefix = "token-prefix"
	// FindingRuleBeforeUserAgent reports an allow or disallow line that
	// precedes every user-agent line. It is dropped rather than attached to the
	// group that follows.
	FindingRuleBeforeUserAgent = "rule-before-user-agent"
	// FindingTruncated reports input past MaxBytes, with the offset where
	// parsing stopped.
	FindingTruncated = "truncated"
)

// Finding is something Parse noticed that a site owner would want to know.
// Findings never change which rule decides a path; they explain the file.
type Finding struct {
	Kind    string // one of the Finding constants above
	Line    int    // 1-based line the finding came from, 0 when it is about the whole file
	Offset  int    // byte offset parsing stopped at, set for FindingTruncated
	Value   string // field value as written, when one line caused the finding
	Message string
}

// File is a parsed robots.txt file.
type File struct {
	Groups   []Group // merged groups, in order of first appearance of the token
	Findings []Finding
}

// Select returns the group that governs the crawler with the given product
// token. The token is compared case-insensitively and as a whole, never as a
// substring of a User-Agent header. When no group names it, the "*" group
// governs; ok is false when the file has neither, and the zero Group returned
// then allows every path.
func (f File) Select(token string) (g Group, ok bool) {
	want := strings.ToLower(token)
	for _, group := range f.Groups {
		if group.Token == want {
			return group, true
		}
		if group.Token == "*" {
			g, ok = group, true
		}
	}
	return g, ok
}

// record is one robots.txt group as written: the consecutive user-agent lines
// and the rules that follow them, before merging by product token.
type record struct {
	tokens []string
	rules  []Rule
}

// Parse reads a robots.txt file and returns the groups it defines, merged by
// product token. Lines it cannot understand are skipped and, where a site
// owner could be surprised, reported in Findings; the only error reported is a
// read failure.
func Parse(r io.Reader) (File, error) {
	data, truncated, err := read(r)
	if err != nil {
		return File{}, err
	}

	var f File
	if truncated {
		f.Findings = append(f.Findings, Finding{
			Kind:    FindingTruncated,
			Offset:  MaxBytes,
			Message: fmt.Sprintf("input past byte %d is ignored, along with the line that offset falls in", MaxBytes),
		})
	}

	var records []record
	startGroup := true
	for line, rest := 1, data; len(rest) > 0; line++ {
		var text string
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			text, rest = string(rest[:i]), rest[i+1:]
		} else {
			text, rest = string(rest), nil
		}
		text = strings.TrimSuffix(text, "\r")
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
				records = append(records, record{})
				startGroup = false
			}
			token, extra := productToken(value)
			if token == "" {
				f.Findings = append(f.Findings, Finding{
					Kind:    FindingNonPortableToken,
					Line:    line,
					Value:   value,
					Message: "not an RFC 9309 product token, Google's parser matches nothing, other crawlers may match substrings",
				})
				continue
			}
			if extra != "" {
				f.Findings = append(f.Findings, Finding{
					Kind:    FindingTokenPrefix,
					Line:    line,
					Value:   value,
					Message: fmt.Sprintf("not a bare RFC 9309 product token, the group is named %q and %q is ignored", token, extra),
				})
			}
			rec := &records[len(records)-1]
			if !slices.Contains(rec.tokens, token) {
				rec.tokens = append(rec.tokens, token)
			}
		case "allow", "disallow":
			kind := Allow
			if field == "disallow" {
				kind = Disallow
			}
			if len(records) == 0 {
				f.Findings = append(f.Findings, Finding{
					Kind:    FindingRuleBeforeUserAgent,
					Line:    line,
					Value:   value,
					Message: fmt.Sprintf("%s before any user-agent line, dropped rather than attached to the group that follows", kind),
				})
				continue
			}
			rec := &records[len(records)-1]
			rec.rules = append(rec.rules, Rule{Kind: kind, Pattern: value, Line: line})
			startGroup = true
		}
	}

	f.Groups = merge(records)
	return f, nil
}

// read returns the input up to MaxBytes. When more follows, the line the limit
// falls in is dropped too, because it was cut.
func read(r io.Reader) (data []byte, truncated bool, err error) {
	data, err = io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) <= MaxBytes {
		return data, false, nil
	}
	data = data[:MaxBytes]
	return data[:bytes.LastIndexByte(data, '\n')+1], true, nil
}

func merge(records []record) []Group {
	var groups []Group
	index := make(map[string]int)
	for _, rec := range records {
		for _, token := range rec.tokens {
			i, ok := index[token]
			if !ok {
				groups = append(groups, Group{Token: token})
				i = len(groups) - 1
				index[token] = i
			}
			groups[i].Rules = append(groups[i].Rules, rec.rules...)
		}
	}
	return groups
}

// productToken splits a user-agent value into the product token it starts with,
// lowercased, and whatever followed it. The grammar in RFC 9309, Section 2.2.1,
// allows letters, '-' and '_'; "*" names the default group, and only on its
// own. The token is empty when the value does not start with one, which names
// no group at all.
func productToken(value string) (token, rest string) {
	if value == "*" {
		return "*", ""
	}
	i := 0
	for i < len(value) && isTokenByte(value[i]) {
		i++
	}
	return strings.ToLower(value[:i]), value[i:]
}

func isTokenByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return true
	}
	return c == '-' || c == '_'
}
