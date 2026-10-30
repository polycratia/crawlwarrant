package purpose

import (
	"strings"
	"testing"
	"time"
)

var read = day(2026, time.October, 19)

func hasReason(reasons []Reason, kind string) bool {
	for _, r := range reasons {
		if r.Kind == kind {
			return true
		}
	}
	return false
}

func TestEveryRowIsCited(t *testing.T) {
	if len(Table) == 0 {
		t.Fatal("Table is empty, want the published crawler tokens")
	}
	for _, row := range Table {
		if !strings.HasPrefix(row.SourceURL, "https://") {
			t.Errorf("%s: SourceURL = %q, want an https URL: a row nobody can check is not cited data", row.Token, row.SourceURL)
		}
		if row.VerifiedOn.IsZero() {
			t.Errorf("%s: no VerifiedOn, want the day the source was read", row.Token)
		}
		if row.Operator == "" {
			t.Errorf("%s: no Operator, want the company whose requests carry the token", row.Token)
		}
		if row.Purpose == 0 {
			t.Errorf("%s: Purpose is unset, want what the operator says the token is for", row.Token)
		}
		if row.RangeFileURL != "" && !strings.HasPrefix(row.RangeFileURL, "https://") {
			t.Errorf("%s: RangeFileURL = %q, want an https URL", row.Token, row.RangeFileURL)
		}
		if row.SignatureAgent != "" && !strings.HasPrefix(row.SignatureAgent, "https://") {
			t.Errorf("%s: SignatureAgent = %q, want an https URL", row.Token, row.SignatureAgent)
		}
		for _, suffix := range row.ReverseDNS {
			if suffix == "" || strings.HasPrefix(suffix, ".") {
				t.Errorf("%s: reverse-DNS suffix %q, want a bare host suffix", row.Token, suffix)
			}
		}
	}
}

func TestTokensAreUnique(t *testing.T) {
	seen := make(map[string]string, len(Table))
	for _, row := range Table {
		key := strings.ToLower(row.Token)
		if first, ok := seen[key]; ok {
			t.Errorf("token %q is in the table twice, as %q and %q", key, first, row.Token)
		}
		seen[key] = row.Token
	}
}

func TestIdentityMaterialMatchesFetching(t *testing.T) {
	for _, row := range Table {
		if row.Fetches && row.RangeFileURL == "" && len(row.ReverseDNS) == 0 && row.SignatureAgent == "" {
			t.Errorf("%s fetches but the row names no way to verify a request", row.Token)
		}
		if !row.Fetches && row.RangeFileURL != "" {
			t.Errorf("%s never fetches but carries the range file %q: there is nothing to verify", row.Token, row.RangeFileURL)
		}
	}
}

func TestGoogleExtendedNeverFetches(t *testing.T) {
	res, ok := Lookup("Google-Extended", read)
	if !ok {
		t.Fatal("Lookup found no row for Google-Extended")
	}
	if res.Row.Purpose != PurposeControlToken {
		t.Errorf("purpose = %v, want %v: the token names a use in robots.txt", res.Row.Purpose, PurposeControlToken)
	}
	if res.Row.Fetches {
		t.Error("Fetches = true, want false: no request is ever sent under Google-Extended")
	}
	if res.Row.RangeFileURL != "" {
		t.Errorf("RangeFileURL = %q, want none: a token that never fetches publishes no ranges", res.Row.RangeFileURL)
	}
	if res.Row.RobotsApplies != RobotsYes {
		t.Errorf("RobotsApplies = %v, want %v: the token exists to be set in robots.txt", res.Row.RobotsApplies, RobotsYes)
	}
	if !hasReason(res.Reasons, ReasonNeverFetches) {
		t.Errorf("reasons = %+v, want a %q reason", res.Reasons, ReasonNeverFetches)
	}
	for _, r := range res.Reasons {
		if r.Message == "" {
			t.Errorf("reason %+v, want a message", r)
		}
	}
}

func TestLookupStaleRow(t *testing.T) {
	fresh, ok := Lookup("GPTBot", read.Add(179*24*time.Hour))
	if !ok {
		t.Fatal("Lookup found no row for GPTBot")
	}
	if hasReason(fresh.Reasons, ReasonStale) {
		t.Errorf("reasons = %+v, want no %q reason within %v of the day the source was read", fresh.Reasons, ReasonStale, StaleAfter)
	}

	stale, _ := Lookup("GPTBot", read.Add(181*24*time.Hour))
	if !hasReason(stale.Reasons, ReasonStale) {
		t.Fatalf("reasons = %+v, want a %q reason past %v", stale.Reasons, ReasonStale, StaleAfter)
	}
	for _, r := range stale.Reasons {
		if r.Kind != ReasonStale {
			continue
		}
		if !strings.Contains(r.Message, stale.Row.SourceURL) || !strings.Contains(r.Message, "2026-10-19") {
			t.Errorf("stale message = %q, want the source URL and the day it was read", r.Message)
		}
	}
}

func TestLookupMatchesWholeTokens(t *testing.T) {
	cases := []struct {
		name  string
		token string
		want  string
	}{
		{"as published", "GPTBot", "GPTBot"},
		{"mixed case", "gPtBoT", "GPTBot"},
		{"lowercased token", "bingbot", "bingbot"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, ok := Lookup(c.token, read)
			if !ok {
				t.Fatalf("Lookup(%q) found no row, want %q", c.token, c.want)
			}
			if res.Row.Token != c.want {
				t.Errorf("Lookup(%q) = %q, want %q", c.token, res.Row.Token, c.want)
			}
		})
	}

	for _, token := range []string{"bot", "mygptbot", "ExampleBot", ""} {
		if res, ok := Lookup(token, read); ok {
			t.Errorf("Lookup(%q) = %+v, want no row: a token is never matched as a substring", token, res.Row)
		}
	}
}

func TestUserInitiatedRowsSayWhatIsUnsettled(t *testing.T) {
	cases := []struct {
		token  string
		want   RobotsApplies
		reason string
	}{
		{"ChatGPT-User", RobotsMayNot, ReasonRobotsMayNot},
		{"Perplexity-User", RobotsUnknown, ReasonRobotsUnknown},
	}
	for _, c := range cases {
		t.Run(c.token, func(t *testing.T) {
			res, ok := Lookup(c.token, read)
			if !ok {
				t.Fatalf("Lookup(%q) found no row", c.token)
			}
			if res.Row.Purpose != PurposeUserInitiated {
				t.Errorf("purpose = %v, want %v", res.Row.Purpose, PurposeUserInitiated)
			}
			if res.Row.RobotsApplies != c.want {
				t.Errorf("RobotsApplies = %v, want %v", res.Row.RobotsApplies, c.want)
			}
			if !hasReason(res.Reasons, c.reason) {
				t.Errorf("reasons = %+v, want a %q reason", res.Reasons, c.reason)
			}
		})
	}
}

func TestStrings(t *testing.T) {
	purposes := []struct {
		purpose Purpose
		want    string
	}{
		{PurposeTraining, "training"},
		{PurposeSearchIndex, "search-index"},
		{PurposeUserInitiated, "user-initiated"},
		{PurposeControlToken, "control-token"},
		{PurposeAds, "ads"},
		{Purpose(0), "unset"},
	}
	for _, c := range purposes {
		if got := c.purpose.String(); got != c.want {
			t.Errorf("Purpose(%d) = %q, want %q", c.purpose, got, c.want)
		}
	}

	applies := []struct {
		applies RobotsApplies
		want    string
	}{
		{RobotsYes, "yes"},
		{RobotsMayNot, "may-not"},
		{RobotsUnknown, "unknown"},
	}
	for _, c := range applies {
		if got := c.applies.String(); got != c.want {
			t.Errorf("RobotsApplies(%d) = %q, want %q", c.applies, got, c.want)
		}
	}
}
