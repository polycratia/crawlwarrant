package robots

import (
	"bytes"
	"errors"
	"fmt"
	"time"
)

// MaxRedirects is the number of consecutive redirects a robots.txt fetch
// follows. RFC 9309, Section 2.3.1.2, asks for at least five; the sixth makes
// the file unavailable.
const MaxRedirects = 5

// Effect is what a fetch outcome does to access.
type Effect uint8

const (
	// EffectUndecided is the zero Effect, carried by a Policy whose status its
	// sources read differently until a Reading is picked.
	EffectUndecided Effect = iota
	// EffectRules means the rules of the fetched file decide each path.
	EffectRules
	// EffectAllowAll means robots.txt is unavailable, so every path is allowed.
	EffectAllowAll
	// EffectDisallowAll means robots.txt is unreachable, so no path is allowed
	// while that lasts.
	EffectDisallowAll
)

func (e Effect) String() string {
	switch e {
	case EffectRules:
		return "rules"
	case EffectAllowAll:
		return "allow all"
	case EffectDisallowAll:
		return "disallow all"
	}
	return "undecided"
}

// Reading names the source whose interpretation a caller chose for a status
// that published sources read differently. The zero value names none: there is
// no default reading, the caller picks one.
type Reading uint8

const (
	ReadingRFC9309 Reading = iota + 1
	ReadingGoogle
)

func (r Reading) String() string {
	switch r {
	case ReadingRFC9309:
		return "rfc9309"
	case ReadingGoogle:
		return "google"
	}
	return "none"
}

// Source is the published document an interpretation is drawn from.
type Source struct {
	Name string
	URL  string
}

var (
	sourceSuccess       = Source{"RFC 9309, Section 2.3.1.1", "https://www.rfc-editor.org/rfc/rfc9309.html#section-2.3.1.1"}
	sourceRedirects     = Source{"RFC 9309, Section 2.3.1.2", "https://www.rfc-editor.org/rfc/rfc9309.html#section-2.3.1.2"}
	sourceUnavailable   = Source{"RFC 9309, Section 2.3.1.3", "https://www.rfc-editor.org/rfc/rfc9309.html#section-2.3.1.3"}
	sourceUnreachable   = Source{"RFC 9309, Section 2.3.1.4", "https://www.rfc-editor.org/rfc/rfc9309.html#section-2.3.1.4"}
	sourceCaching       = Source{"RFC 9309, Section 2.4", "https://www.rfc-editor.org/rfc/rfc9309.html#section-2.4"}
	sourceGoogleCodes   = Source{"Google robots.txt specification, handling HTTP result codes", "https://developers.google.com/search/docs/crawling-indexing/robots/robots_txt#handling-http-result-codes"}
	sourceGoogleCaching = Source{"Google robots.txt specification, caching", "https://developers.google.com/search/docs/crawling-indexing/robots/robots_txt#caching"}
)

// Outcome is one recorded robots.txt fetch. It is data the caller already has,
// so FromFetch never touches the network.
type Outcome struct {
	Status    int    // final HTTP status, 0 when no response arrived
	Redirects int    // consecutive redirects followed before Status
	Body      []byte // body as fetched, read only for a 2xx status
	Err       error  // transport error, when the fetch did not complete
}

// Policy is what a recorded fetch means for access to a site.
type Policy struct {
	// Effect is what the outcome does to access. It is EffectUndecided exactly
	// while Divergence is set and no Reading has been picked.
	Effect Effect
	Status int    // status the outcome recorded, 0 when none arrived
	Reason string // one line naming the status and what it does
	Source Source // published rule the effect comes from
	File   File   // parsed file, set when Effect is EffectRules
	// Divergence is set when published sources read Status differently. Under
	// resolves it.
	Divergence *Divergence
}

// Divergence is a status whose meaning published sources disagree about.
type Divergence struct {
	Status          int
	Interpretations []Interpretation
}

// Interpretation is how one source reads a divergent status.
type Interpretation struct {
	Reading Reading
	Effect  Effect
	Source  Source
	Reason  string
}

// Divergences holds the statuses published sources read differently. Status
// 429 is the only one: RFC 9309 has no rule for it beyond its class, which
// makes it an unavailable 4xx, while Google documents it with the server
// errors. A Policy for such a status carries the readings instead of an
// Effect.
var Divergences = []Divergence{
	{
		Status: 429,
		Interpretations: []Interpretation{
			{
				Reading: ReadingRFC9309,
				Effect:  EffectAllowAll,
				Source:  sourceUnavailable,
				Reason:  "status 429 is a 4xx, an unavailable status: everything is allowed",
			},
			{
				Reading: ReadingGoogle,
				Effect:  EffectDisallowAll,
				Source:  sourceGoogleCodes,
				Reason:  "status 429 is documented with the server errors: currently disallowing everything",
			},
		},
	},
}

// ErrReadingRequired reports that a divergent Policy was used without naming
// the reading to apply.
var ErrReadingRequired = errors.New("a status its sources read differently needs an explicit Reading")

// Freshness is one published limit on how long a fetched robots.txt may be
// reused before it has to be fetched again.
type Freshness struct {
	Limit  time.Duration
	Source Source
	Note   string
}

// FreshFor holds the published caching limits, as data for a caller to apply
// to its own records: FromFetch reads a single outcome and never looks at a
// clock.
var FreshFor = []Freshness{
	{
		Limit:  24 * time.Hour,
		Source: sourceCaching,
		Note:   "crawlers SHOULD NOT use a cached robots.txt for more than 24 hours, unless it cannot be fetched again",
	},
	{
		Limit:  24 * time.Hour,
		Source: sourceGoogleCaching,
		Note:   "Google generally caches robots.txt for up to 24 hours, and longer when a refetch fails",
	},
}

// Unreachability is one published step in what happens while robots.txt stays
// unreachable, taking effect once After has elapsed.
type Unreachability struct {
	After  time.Duration
	Effect Effect
	Source Source
	Note   string
}

// WhileUnreachable holds the published sequences for a robots.txt that stays
// unreachable, each source's rows in order of After. Like FreshFor, these are
// rows of data: a caller that tracks how long a site has been failing decides
// which row it is on.
var WhileUnreachable = []Unreachability{
	{
		After:  0,
		Effect: EffectDisallowAll,
		Source: sourceUnreachable,
		Note:   "a 5xx or a network error is a complete disallow while it lasts",
	},
	{
		After:  30 * 24 * time.Hour,
		Effect: EffectAllowAll,
		Source: sourceUnreachable,
		Note:   "after more than 30 days unreachable, a crawler MAY read the file as unavailable, which allows everything, or keep using a cached copy",
	},
	{
		After:  0,
		Effect: EffectDisallowAll,
		Source: sourceGoogleCodes,
		Note:   "Google stops crawling the site for the first 12 hours of server errors",
	},
	{
		After:  12 * time.Hour,
		Effect: EffectRules,
		Source: sourceGoogleCodes,
		Note:   "past 12 hours Google uses its last cached robots.txt, when it has one",
	},
	{
		After:  30 * 24 * time.Hour,
		Effect: EffectAllowAll,
		Source: sourceGoogleCodes,
		Note:   "with no cached copy, after 30 days Google crawls the site as if it had no robots.txt, when the site is otherwise available",
	},
}

// FromFetch reads a recorded fetch as policy, following RFC 9309, Section
// 2.3.1. The body is parsed only for a 2xx status; every other outcome decides
// on its own, without rules.
func FromFetch(o Outcome) Policy {
	if o.Err != nil {
		return Policy{
			Effect: EffectDisallowAll,
			Status: o.Status,
			Source: sourceUnreachable,
			Reason: fmt.Sprintf("the fetch did not complete (%v): currently disallowing everything", o.Err),
		}
	}
	if o.Status == 0 {
		return Policy{
			Effect: EffectDisallowAll,
			Source: sourceUnreachable,
			Reason: "the fetch recorded no status: currently disallowing everything",
		}
	}
	if o.Redirects > MaxRedirects {
		return Policy{
			Effect: EffectAllowAll,
			Status: o.Status,
			Source: sourceRedirects,
			Reason: fmt.Sprintf("redirect %d goes past the %d a crawler follows: robots.txt is unavailable, everything is allowed", o.Redirects, MaxRedirects),
		}
	}
	if d, ok := divergence(o.Status); ok {
		return Policy{
			Status:     o.Status,
			Reason:     fmt.Sprintf("status %d is read differently by its sources: the caller picks a Reading", o.Status),
			Divergence: &d,
		}
	}

	switch o.Status / 100 {
	case 2:
		file, _ := Parse(bytes.NewReader(o.Body)) // a bytes.Reader cannot fail
		return Policy{
			Effect: EffectRules,
			Status: o.Status,
			Source: sourceSuccess,
			Reason: fmt.Sprintf("status %d: the rules in the body decide", o.Status),
			File:   file,
		}
	case 3:
		return Policy{
			Effect: EffectAllowAll,
			Status: o.Status,
			Source: sourceRedirects,
			Reason: fmt.Sprintf("status %d after %d redirects reaches no file: robots.txt is unavailable, everything is allowed", o.Status, o.Redirects),
		}
	case 4:
		return Policy{
			Effect: EffectAllowAll,
			Status: o.Status,
			Source: sourceUnavailable,
			Reason: fmt.Sprintf("status %d: robots.txt is unavailable, everything is allowed", o.Status),
		}
	case 5:
		return Policy{
			Effect: EffectDisallowAll,
			Status: o.Status,
			Source: sourceUnreachable,
			Reason: fmt.Sprintf("status %d: currently disallowing everything", o.Status),
		}
	}
	return Policy{
		Effect: EffectAllowAll,
		Status: o.Status,
		Source: sourceUnavailable,
		Reason: fmt.Sprintf("status %d is outside the classes RFC 9309 covers: read as unavailable, everything is allowed", o.Status),
	}
}

// Under returns the policy as the given Reading reads it. A policy with no
// Divergence is returned unchanged, because nothing about it depends on the
// reading. ErrReadingRequired is returned when the policy is divergent and the
// Reading is not one it carries, the zero Reading included: there is no
// default.
func (p Policy) Under(r Reading) (Policy, error) {
	if p.Divergence == nil {
		return p, nil
	}
	for _, i := range p.Divergence.Interpretations {
		if i.Reading == r {
			p.Effect, p.Source, p.Reason = i.Effect, i.Source, i.Reason
			return p, nil
		}
	}
	return Policy{}, fmt.Errorf("robots: reading %v does not read status %d: %w", r, p.Divergence.Status, ErrReadingRequired)
}

func divergence(status int) (Divergence, bool) {
	for _, d := range Divergences {
		if d.Status == status {
			return d, true
		}
	}
	return Divergence{}, false
}
