package robots

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Signal is what the Content-Signal lines of a group say about one use.
type Signal uint8

const (
	// SignalUnset is the zero Signal: the group never gave the key, so it
	// grants nothing and refuses nothing. It is never reported as a no.
	SignalUnset Signal = iota
	// SignalYes grants the use the key names.
	SignalYes
	// SignalNo refuses the use the key names.
	SignalNo
)

func (s Signal) String() string {
	switch s {
	case SignalYes:
		return "yes"
	case SignalNo:
		return "no"
	}
	return "unset"
}

// SignalKeys are the keys the Content Signals Policy
// (https://contentsignals.org) defines, in the order it lists them. Each one
// takes yes or no; any other key is ignored and reported.
var SignalKeys = []string{"search", "ai-input", "ai-train"}

// ContentSignal is what the Content-Signal lines of a group declare. A key the
// group never gave stays SignalUnset, which neither grants nor refuses the use
// it names, so a declaration that omits a key leaves that question open.
//
// AI summaries and retrieval-augmented generation fall under AIInput rather
// than Search: the policy defines search as building an index and returning
// links and short excerpts, and excludes AI-generated search summaries from
// that definition, while ai-input covers taking content into a model to answer
// with, retrieval-augmented generation included. A group that grants search
// and leaves ai-input unset has said nothing about either of them.
type ContentSignal struct {
	Search  Signal
	AIInput Signal
	AITrain Signal
}

// Key returns the Signal for one of SignalKeys, and SignalUnset for any other
// name.
func (c ContentSignal) Key(name string) Signal {
	switch name {
	case "search":
		return c.Search
	case "ai-input":
		return c.AIInput
	case "ai-train":
		return c.AITrain
	}
	return SignalUnset
}

func (c *ContentSignal) set(name string, s Signal) {
	switch name {
	case "search":
		c.Search = s
	case "ai-input":
		c.AIInput = s
	case "ai-train":
		c.AITrain = s
	}
}

// signalEntry is one key=value pair as a Content-Signal line gave it, before
// the entries of a group are folded into a ContentSignal.
type signalEntry struct {
	key   string
	value Signal
	line  int
}

// parseSignals reads the value of one Content-Signal line into its pairs. A
// key the policy does not define, and a value that is neither yes nor no, are
// left out and reported; the rest of the line still counts.
func parseSignals(value string, line int) (entries []signalEntry, findings []Finding) {
	for _, pair := range strings.Split(value, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		name, val, ok := strings.Cut(pair, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		val = strings.ToLower(strings.TrimSpace(val))
		switch {
		case !ok || name == "":
			findings = append(findings, Finding{
				Kind:    FindingMalformedSignal,
				Line:    line,
				Value:   pair,
				Message: "not a key=value pair of a Content-Signal line, ignored",
			})
		case !slices.Contains(SignalKeys, name):
			findings = append(findings, Finding{
				Kind:    FindingUnknownSignalKey,
				Line:    line,
				Value:   pair,
				Message: fmt.Sprintf("%q is not a key the Content Signals Policy defines, ignored", name),
			})
		case val == "yes":
			entries = append(entries, signalEntry{key: name, value: SignalYes, line: line})
		case val == "no":
			entries = append(entries, signalEntry{key: name, value: SignalNo, line: line})
		default:
			findings = append(findings, Finding{
				Kind:    FindingMalformedSignal,
				Line:    line,
				Value:   pair,
				Message: fmt.Sprintf("%s takes yes or no, %q is neither, ignored", name, val),
			})
		}
	}
	return entries, findings
}

// resolveSignals folds the Content-Signal entries of one group, in file order,
// into a single ContentSignal. A key given twice with the same value is left as
// it is; given twice with different values it resolves to no, the value that
// restricts, and the conflict is reported with the lines it came from.
func resolveSignals(entries []signalEntry) (ContentSignal, []Finding) {
	var c ContentSignal
	var findings []Finding
	for _, key := range SignalKeys {
		var (
			value    Signal
			lines    []int
			conflict bool
		)
		for _, e := range entries {
			if e.key != key {
				continue
			}
			if len(lines) == 0 || lines[len(lines)-1] != e.line {
				lines = append(lines, e.line)
			}
			switch {
			case value == SignalUnset:
				value = e.value
			case e.value != value:
				conflict = true
			}
		}
		if conflict {
			value = SignalNo
			findings = append(findings, Finding{
				Kind:    FindingSignalConflict,
				Line:    lines[0],
				Lines:   lines,
				Value:   key,
				Message: fmt.Sprintf("%s is given more than once with different values, on %s: resolved to no, the value that restricts", key, describeLines(lines)),
			})
		}
		c.set(key, value)
	}
	return c, findings
}

func describeLines(lines []int) string {
	texts := make([]string, len(lines))
	for i, line := range lines {
		texts[i] = strconv.Itoa(line)
	}
	if len(texts) == 1 {
		return "line " + texts[0]
	}
	return "lines " + strings.Join(texts[:len(texts)-1], ", ") + " and " + texts[len(texts)-1]
}
