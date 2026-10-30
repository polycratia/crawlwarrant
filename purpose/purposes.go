// Package purpose holds what each published AI crawler product token is for:
// who operates it, what it fetches for, whether it fetches at all, whether
// robots.txt applies to it, and where the operator publishes the material an
// identity check needs. Every row names the document it was read from and the
// day it was read; nothing in the table is fetched at runtime.
package purpose

import (
	"fmt"
	"strings"
	"time"
)

// StaleAfter is how long a row may be relied on after the day its source was
// read. Operators revise these documents without notice, so past this age
// Lookup adds ReasonStale instead of hiding the row: the row is still what was
// published, it is just no longer fresh.
const StaleAfter = 180 * 24 * time.Hour

const dateLayout = "2006-01-02"

// Purpose is what an operator says a product token is for.
type Purpose uint8

const (
	// PurposeTraining collects content to train a model on.
	PurposeTraining Purpose = iota + 1
	// PurposeSearchIndex builds an index that answers link back to.
	PurposeSearchIndex
	// PurposeUserInitiated is a fetch one person asked for, in the moment.
	PurposeUserInitiated
	// PurposeControlToken names a use in robots.txt and fetches nothing.
	PurposeControlToken
	// PurposeAds crawls for advertising.
	PurposeAds
)

func (p Purpose) String() string {
	switch p {
	case PurposeTraining:
		return "training"
	case PurposeSearchIndex:
		return "search-index"
	case PurposeUserInitiated:
		return "user-initiated"
	case PurposeControlToken:
		return "control-token"
	case PurposeAds:
		return "ads"
	}
	return "unset"
}

// RobotsApplies is what the operator publishes about robots.txt binding a
// token.
type RobotsApplies uint8

const (
	// RobotsUnknown is the zero value: the operator publishes nothing either
	// way, so an audit cannot read an ignored rule as a violation.
	RobotsUnknown RobotsApplies = iota
	// RobotsYes means the operator documents that the token obeys robots.txt.
	RobotsYes
	// RobotsMayNot means the operator documents that robots.txt may not apply,
	// as it says of fetches a person asked for.
	RobotsMayNot
)

func (r RobotsApplies) String() string {
	switch r {
	case RobotsYes:
		return "yes"
	case RobotsMayNot:
		return "may-not"
	}
	return "unknown"
}

// Row is one product token as its operator publishes it.
type Row struct {
	Token          string        // product token, as the operator spells it
	Operator       string        // company whose requests carry the token
	Purpose        Purpose       // what the operator says the token is for
	Fetches        bool          // whether any request is sent under the token
	RobotsApplies  RobotsApplies // what the operator says about robots.txt
	RangeFileURL   string        // published IP range file, empty when none
	ReverseDNS     []string      // host suffixes a reverse lookup must end in, empty when none published
	SignatureAgent string        // Signature-Agent URL whose key directory signs the requests, empty when none
	SourceURL      string        // document the row was read from
	VerifiedOn     time.Time     // day that document was read
}

// Kinds of Reason.
const (
	// ReasonStale reports a row whose source was read more than StaleAfter
	// before the time Lookup was given.
	ReasonStale = "purpose row stale"
	// ReasonNeverFetches reports a token no request is sent under, so no
	// request can be matched against published identity material.
	ReasonNeverFetches = "token never fetches"
	// ReasonRobotsMayNot reports a token its operator documents as possibly not
	// bound by robots.txt.
	ReasonRobotsMayNot = "robots may not apply"
	// ReasonRobotsUnknown reports a token whose operator publishes nothing
	// about robots.txt.
	ReasonRobotsUnknown = "robots applicability unknown"
)

// Reason is something a caller should know before acting on a row.
type Reason struct {
	Kind    string // one of the Reason constants above
	Message string
}

// Result is a row together with what the caller should know about using it.
type Result struct {
	Row     Row
	Reasons []Reason
}

// Lookup returns the row for a product token, compared case-insensitively and
// as a whole, never as a substring of a User-Agent header. ok is false when the
// table names no such token, which is not a verdict: an unlisted token is
// unlisted, not an impostor.
func Lookup(token string, now time.Time) (Result, bool) {
	want := strings.ToLower(strings.TrimSpace(token))
	for _, row := range Table {
		if strings.ToLower(row.Token) != want {
			continue
		}
		return Result{Row: row, Reasons: row.reasons(now)}, true
	}
	return Result{}, false
}

func (r Row) reasons(now time.Time) []Reason {
	var reasons []Reason
	if !r.Fetches {
		reasons = append(reasons, Reason{
			Kind:    ReasonNeverFetches,
			Message: fmt.Sprintf("%s names a use rather than a fetcher: the operator sends no requests under it, so a request carrying it matches no published range and can only be weighed as a claim", r.Token),
		})
	}
	switch r.RobotsApplies {
	case RobotsMayNot:
		reasons = append(reasons, Reason{
			Kind:    ReasonRobotsMayNot,
			Message: fmt.Sprintf("the operator documents that robots.txt may not apply to %s, because the fetch is one a person asked for: a rule it passed is not by itself a violation", r.Token),
		})
	case RobotsUnknown:
		reasons = append(reasons, Reason{
			Kind:    ReasonRobotsUnknown,
			Message: fmt.Sprintf("the operator publishes nothing about robots.txt applying to %s: an audit cannot call a rule it passed a violation", r.Token),
		})
	}
	if age := now.Sub(r.VerifiedOn); age > StaleAfter {
		reasons = append(reasons, Reason{
			Kind: ReasonStale,
			Message: fmt.Sprintf("read from %s on %s, %d days before this check, past the %d-day limit: read the source again before relying on the row",
				r.SourceURL, r.VerifiedOn.Format(dateLayout), int(age/(24*time.Hour)), int(StaleAfter/(24*time.Hour))),
		})
	}
	return reasons
}

func day(year int, month time.Month, d int) time.Time {
	return time.Date(year, month, d, 0, 0, 0, 0, time.UTC)
}

// Table is the published purpose of every product token this package knows, in
// order of operator. It is cited data: each row carries the document it was
// read from and the day it was read, and no row is refreshed at runtime.
var Table = []Row{
	{
		Token:         "GPTBot",
		Operator:      "OpenAI",
		Purpose:       PurposeTraining,
		Fetches:       true,
		RobotsApplies: RobotsYes,
		RangeFileURL:  "https://openai.com/gptbot.json",
		SourceURL:     "https://developers.openai.com/api/docs/bots",
		VerifiedOn:    day(2026, time.October, 19),
	},
	{
		Token:         "OAI-SearchBot",
		Operator:      "OpenAI",
		Purpose:       PurposeSearchIndex,
		Fetches:       true,
		RobotsApplies: RobotsYes,
		RangeFileURL:  "https://openai.com/searchbot.json",
		SourceURL:     "https://developers.openai.com/api/docs/bots",
		VerifiedOn:    day(2026, time.October, 19),
	},
	{
		Token:          "ChatGPT-User",
		Operator:       "OpenAI",
		Purpose:        PurposeUserInitiated,
		Fetches:        true,
		RobotsApplies:  RobotsMayNot,
		RangeFileURL:   "https://openai.com/chatgpt-user.json",
		SignatureAgent: "https://chatgpt.com/.well-known/http-message-signatures-directory",
		SourceURL:      "https://developers.openai.com/api/docs/bots",
		VerifiedOn:     day(2026, time.October, 19),
	},
	{
		Token:         "OAI-AdsBot",
		Operator:      "OpenAI",
		Purpose:       PurposeAds,
		Fetches:       true,
		RobotsApplies: RobotsYes,
		RangeFileURL:  "https://openai.com/adsbot.json",
		SourceURL:     "https://developers.openai.com/api/docs/bots",
		VerifiedOn:    day(2026, time.October, 19),
	},
	{
		Token:         "ClaudeBot",
		Operator:      "Anthropic",
		Purpose:       PurposeTraining,
		Fetches:       true,
		RobotsApplies: RobotsYes,
		RangeFileURL:  "https://claude.com/crawling/bots.json",
		SourceURL:     "https://support.anthropic.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler",
		VerifiedOn:    day(2026, time.October, 19),
	},
	{
		Token:         "Claude-SearchBot",
		Operator:      "Anthropic",
		Purpose:       PurposeSearchIndex,
		Fetches:       true,
		RobotsApplies: RobotsYes,
		RangeFileURL:  "https://claude.com/crawling/bots.json",
		SourceURL:     "https://support.anthropic.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler",
		VerifiedOn:    day(2026, time.October, 19),
	},
	{
		Token:         "Claude-User",
		Operator:      "Anthropic",
		Purpose:       PurposeUserInitiated,
		Fetches:       true,
		RobotsApplies: RobotsYes,
		RangeFileURL:  "https://claude.com/crawling/bots.json",
		SourceURL:     "https://support.anthropic.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler",
		VerifiedOn:    day(2026, time.October, 19),
	},
	{
		Token:         "Googlebot",
		Operator:      "Google",
		Purpose:       PurposeSearchIndex,
		Fetches:       true,
		RobotsApplies: RobotsYes,
		RangeFileURL:  "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
		ReverseDNS:    []string{"crawl.googlebot.com", "googlebot.com"},
		SourceURL:     "https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot",
		VerifiedOn:    day(2026, time.October, 19),
	},
	{
		Token:         "Google-Extended",
		Operator:      "Google",
		Purpose:       PurposeControlToken,
		Fetches:       false,
		RobotsApplies: RobotsYes,
		SourceURL:     "https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers",
		VerifiedOn:    day(2026, time.October, 19),
	},
	{
		Token:         "PerplexityBot",
		Operator:      "Perplexity",
		Purpose:       PurposeSearchIndex,
		Fetches:       true,
		RobotsApplies: RobotsYes,
		RangeFileURL:  "https://www.perplexity.ai/perplexitybot.json",
		SourceURL:     "https://docs.perplexity.ai/guides/bots",
		VerifiedOn:    day(2026, time.October, 19),
	},
	{
		Token:         "Perplexity-User",
		Operator:      "Perplexity",
		Purpose:       PurposeUserInitiated,
		Fetches:       true,
		RobotsApplies: RobotsUnknown,
		RangeFileURL:  "https://www.perplexity.ai/perplexity-user.json",
		SourceURL:     "https://docs.perplexity.ai/guides/bots",
		VerifiedOn:    day(2026, time.October, 19),
	},
	{
		Token:         "bingbot",
		Operator:      "Microsoft",
		Purpose:       PurposeSearchIndex,
		Fetches:       true,
		RobotsApplies: RobotsYes,
		RangeFileURL:  "https://www.bing.com/toolbox/bingbot.json",
		ReverseDNS:    []string{"search.msn.com"},
		SourceURL:     "https://www.bing.com/webmasters/help/how-to-verify-bingbot-3905dc26",
		VerifiedOn:    day(2026, time.October, 19),
	},
}
