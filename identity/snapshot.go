package identity

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// DefaultMaxAge is how long a snapshot is used when it sets no MaxAge of its
// own. Operators rotate addresses without notice.
const DefaultMaxAge = 24 * time.Hour

// ErrCloudRangeList reports a range file that is a general cloud provider
// list. Such a list covers every address a customer of that provider can rent,
// so a match proves hosting, not a crawler.
var ErrCloudRangeList = errors.New("identity: a general cloud provider range list proves hosting, not a crawler")

// Snapshot is one recorded fetch of the IP range file an operator publishes
// for its crawlers, with the dates a match has to be read against.
type Snapshot struct {
	Operator     string         // company that publishes the file
	Tokens       []string       // product tokens the operator publishes it for
	URL          string         // URL the file was requested from
	FinalURL     string         // URL that answered, set when it differs
	CreationTime time.Time      // creationTime the operator put in the file
	FetchedAt    time.Time      // when we read it
	MaxAge       time.Duration  // how long it may be used, DefaultMaxAge when zero
	Prefixes     []netip.Prefix // ranges the file listed
}

// cloudList is one general cloud provider range list, matched by the host that
// serves it with either an exact path or a path fragment.
type cloudList struct {
	host     string
	path     string
	fragment string
	note     string
}

var cloudLists = []cloudList{
	{host: "ip-ranges.amazonaws.com", path: "/ip-ranges.json", note: "AWS lists every address its customers can rent"},
	{host: "www.gstatic.com", path: "/ipranges/cloud.json", note: "Google Cloud lists the addresses of customer workloads"},
	{host: "www.gstatic.com", path: "/ipranges/goog.json", note: "this file lists Google's whole address space, not its crawlers"},
	{host: "download.microsoft.com", fragment: "servicetags", note: "Azure service tags cover every tenant in a region"},
}

func cloudRangeList(rawURL string) (cloudList, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return cloudList{}, false
	}
	host, path := strings.ToLower(u.Hostname()), strings.ToLower(u.Path)
	for _, c := range cloudLists {
		if host != c.host {
			continue
		}
		if c.path != "" && path == c.path {
			return c, true
		}
		if c.fragment != "" && strings.Contains(path, c.fragment) {
			return c, true
		}
	}
	return cloudList{}, false
}

// Load records a fetched range file as a snapshot. A general cloud provider
// list is refused here, at load, rather than left to verify requests it cannot
// speak for, and so is one a redirect led to.
func Load(s Snapshot) (Snapshot, error) {
	if s.URL == "" {
		return Snapshot{}, errors.New("identity: a range snapshot needs the URL it was fetched from")
	}
	for _, u := range []string{s.URL, s.FinalURL} {
		if u == "" {
			continue
		}
		if c, ok := cloudRangeList(u); ok {
			return Snapshot{}, fmt.Errorf("identity: %s: %s: %w", u, c.note, ErrCloudRangeList)
		}
	}
	if s.MaxAge == 0 {
		s.MaxAge = DefaultMaxAge
	}
	return s, nil
}

// Redirected reports whether another URL answered for the published one.
func (s Snapshot) Redirected() bool {
	return s.FinalURL != "" && s.FinalURL != s.URL
}

func (s Snapshot) source() string {
	if s.FinalURL != "" {
		return s.FinalURL
	}
	return s.URL
}

func (s Snapshot) maxAge() time.Duration {
	if s.MaxAge > 0 {
		return s.MaxAge
	}
	return DefaultMaxAge
}

// Verify matches a client address against the snapshot. Past the snapshot's max
// age nothing is verified until the file is fetched again; a file several tokens
// share verifies the operator and says so, not which of its products sent the
// request.
func (s Snapshot) Verify(ip netip.Addr, token string, now time.Time) Evidence {
	e := Evidence{Token: token, Operator: s.Operator, Detail: s.source()}
	if s.Redirected() {
		e.Reasons = append(e.Reasons, Reason{ReasonSnapshotRedirected, fmt.Sprintf("%s answered for %s: the file is re-verified at its published URL before it is trusted again", s.FinalURL, s.URL)})
	}
	if s.CreationTime.IsZero() {
		e.Reasons = append(e.Reasons, Reason{ReasonNoCreationTime, fmt.Sprintf("%s carried no creationTime: how old the operator's own data is cannot be read from the file", s.source())})
	}
	if age := now.Sub(s.FetchedAt); age > s.maxAge() {
		e.Reasons = append(e.Reasons, Reason{ReasonSnapshotStale, fmt.Sprintf("%s was fetched %s, %d hours ago, past the %d hours it may be used: nothing is verified against it until it is fetched again", s.source(), s.FetchedAt.UTC().Format(time.RFC3339), int(age/time.Hour), int(s.maxAge()/time.Hour))})
		return e
	}
	if !s.contains(ip) {
		e.Reasons = append(e.Reasons, Reason{ReasonOutOfRange, fmt.Sprintf("%s is in no prefix of %s", ip, s.source())})
		return e
	}
	e.Kind = EvidenceRange
	e.Reasons = append(e.Reasons, Reason{ReasonInRange, fmt.Sprintf("%s is inside a prefix of %s, fetched %s", ip, s.source(), s.FetchedAt.UTC().Format(time.RFC3339))})
	if len(s.Tokens) > 1 {
		e.Reasons = append(e.Reasons, Reason{ReasonOperatorOnly, fmt.Sprintf("%s publishes %s for %s: the address proves the operator, not which of its products sent the request", s.Operator, s.source(), strings.Join(s.Tokens, ", "))})
	}
	return e
}

func (s Snapshot) contains(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range s.Prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
