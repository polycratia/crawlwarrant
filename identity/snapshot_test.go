package identity

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var fetched = time.Date(2026, time.November, 2, 12, 0, 0, 0, time.UTC)

func load(t *testing.T, s Snapshot) Snapshot {
	t.Helper()
	got, err := Load(s)
	if err != nil {
		t.Fatalf("Load(%s): %v", s.URL, err)
	}
	return got
}

func prefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("ParsePrefix(%q): %v", c, err)
		}
		out = append(out, p)
	}
	return out
}

func gptbotSnapshot(t *testing.T) Snapshot {
	t.Helper()
	return load(t, Snapshot{
		Operator:     "OpenAI",
		Tokens:       []string{"GPTBot"},
		URL:          "https://openai.com/gptbot.json",
		CreationTime: fetched.Add(-2 * time.Hour),
		FetchedAt:    fetched,
		Prefixes:     prefixes(t, "203.0.113.0/24", "2001:db8::/32"),
	})
}

func TestLoadRefusesGeneralCloudRangeLists(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{"aws ip-ranges", "https://ip-ranges.amazonaws.com/ip-ranges.json"},
		{"google cloud", "https://www.gstatic.com/ipranges/cloud.json"},
		{"google address space", "https://www.gstatic.com/ipranges/goog.json"},
		{"azure service tags", "https://download.microsoft.com/download/7/1/D/ServiceTags_Public_20261019.json"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(Snapshot{Operator: "Example", URL: c.url, FetchedAt: fetched})
			if !errors.Is(err, ErrCloudRangeList) {
				t.Fatalf("Load(%q) error = %v, want %v: the file covers every address a customer can rent", c.url, err, ErrCloudRangeList)
			}
			if !strings.Contains(err.Error(), c.url) {
				t.Errorf("error = %q, want it to name the refused URL", err)
			}
		})
	}
}

func TestLoadRefusesACloudListARedirectLedTo(t *testing.T) {
	_, err := Load(Snapshot{
		Operator:  "Example",
		URL:       "https://crawler.example.com/ranges.json",
		FinalURL:  "https://ip-ranges.amazonaws.com/ip-ranges.json",
		FetchedAt: fetched,
	})
	if !errors.Is(err, ErrCloudRangeList) {
		t.Fatalf("error = %v, want %v: where the fetch ended decides what the file proves", err, ErrCloudRangeList)
	}
}

func TestLoadNeedsTheURLItWasFetchedFrom(t *testing.T) {
	_, err := Load(Snapshot{Operator: "Example", FetchedAt: fetched})
	if err == nil {
		t.Fatal("Load with no URL succeeded, want an error: a snapshot nobody can re-fetch cites nothing")
	}
	if errors.Is(err, ErrCloudRangeList) {
		t.Errorf("error = %v, want a missing-URL error rather than a cloud list refusal", err)
	}
}

func TestLoadKeepsAVendorFileAndFillsInTheMaxAge(t *testing.T) {
	s := load(t, Snapshot{Operator: "OpenAI", URL: "https://openai.com/gptbot.json", FetchedAt: fetched})
	if s.MaxAge != DefaultMaxAge {
		t.Errorf("MaxAge = %v, want the default %v", s.MaxAge, DefaultMaxAge)
	}

	s = load(t, Snapshot{Operator: "OpenAI", URL: "https://openai.com/gptbot.json", FetchedAt: fetched, MaxAge: time.Hour})
	if s.MaxAge != time.Hour {
		t.Errorf("MaxAge = %v, want the hour the caller set", s.MaxAge)
	}
}

func TestVerifyAddressInsideAPublishedRange(t *testing.T) {
	s := gptbotSnapshot(t)
	for _, addr := range []string{"203.0.113.7", "::ffff:203.0.113.7", "2001:db8::1"} {
		ev := s.Verify(netip.MustParseAddr(addr), "GPTBot", fetched.Add(time.Hour))
		if ev.Kind != EvidenceRange || !ev.Kind.Verifies() {
			t.Fatalf("%s: kind = %v, want %v: an address inside a fresh range verifies the token", addr, ev.Kind, EvidenceRange)
		}
		if ev.Token != "GPTBot" || ev.Operator != "OpenAI" || ev.Detail != s.URL {
			t.Errorf("%s: evidence = %+v, want the token, the operator and the file it came from", addr, ev)
		}
		if !hasReason(ev.Reasons, ReasonInRange) {
			t.Errorf("%s: reasons = %+v, want a %q reason", addr, ev.Reasons, ReasonInRange)
		}
		for _, kind := range []string{ReasonOperatorOnly, ReasonNoCreationTime, ReasonSnapshotRedirected, ReasonSnapshotStale} {
			if hasReason(ev.Reasons, kind) {
				t.Errorf("%s: reasons = %+v, want no %q reason", addr, ev.Reasons, kind)
			}
		}
	}
}

func TestVerifyAddressOutsideThePublishedRange(t *testing.T) {
	ev := gptbotSnapshot(t).Verify(netip.MustParseAddr("198.51.100.4"), "GPTBot", fetched.Add(time.Hour))
	if ev.Kind.Verifies() {
		t.Fatalf("kind = %v, want nothing verified", ev.Kind)
	}
	if !hasReason(ev.Reasons, ReasonOutOfRange) {
		t.Fatalf("reasons = %+v, want a %q reason", ev.Reasons, ReasonOutOfRange)
	}
	if got := reasonMessage(ev.Reasons, ReasonOutOfRange); !strings.Contains(got, "198.51.100.4") || !strings.Contains(got, "https://openai.com/gptbot.json") {
		t.Errorf("message = %q, want the address and the file it was matched against", got)
	}
}

func TestVerifyPastTheMaxAgeVerifiesNothing(t *testing.T) {
	cases := []struct {
		name   string
		maxAge time.Duration
		now    time.Time
	}{
		{"past the default max age", 0, fetched.Add(DefaultMaxAge + time.Minute)},
		{"past the max age the caller set", time.Hour, fetched.Add(90 * time.Minute)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := Snapshot{
				Operator:     "OpenAI",
				Tokens:       []string{"GPTBot"},
				URL:          "https://openai.com/gptbot.json",
				CreationTime: fetched.Add(-time.Hour),
				FetchedAt:    fetched,
				MaxAge:       c.maxAge,
				Prefixes:     prefixes(t, "203.0.113.0/24"),
			}
			ev := s.Verify(netip.MustParseAddr("203.0.113.7"), "GPTBot", c.now)
			if ev.Kind.Verifies() {
				t.Fatalf("kind = %v, want nothing verified against a snapshot past its max age", ev.Kind)
			}
			if hasReason(ev.Reasons, ReasonInRange) {
				t.Errorf("reasons = %+v, want no %q reason: the file is not read at all once it is stale", ev.Reasons, ReasonInRange)
			}
			got := reasonMessage(ev.Reasons, ReasonSnapshotStale)
			if got == "" {
				t.Fatalf("reasons = %+v, want a %q reason", ev.Reasons, ReasonSnapshotStale)
			}
			if !strings.Contains(got, "https://openai.com/gptbot.json") || !strings.Contains(got, "2026-11-02T12:00:00Z") {
				t.Errorf("message = %q, want the file and when it was fetched", got)
			}
		})
	}

	fresh := gptbotSnapshot(t)
	ev := fresh.Verify(netip.MustParseAddr("203.0.113.7"), "GPTBot", fetched.Add(DefaultMaxAge))
	if ev.Kind != EvidenceRange {
		t.Errorf("kind at exactly the max age = %v, want %v", ev.Kind, EvidenceRange)
	}
}

func TestVerifyRedirectedSourceIsFlagged(t *testing.T) {
	s := load(t, Snapshot{
		Operator:     "Example",
		Tokens:       []string{"ExampleBot"},
		URL:          "https://example.com/crawler-ranges.json",
		FinalURL:     "https://cdn.example.net/crawler-ranges.json",
		CreationTime: fetched.Add(-time.Hour),
		FetchedAt:    fetched,
		Prefixes:     prefixes(t, "203.0.113.0/24"),
	})
	if !s.Redirected() {
		t.Fatal("Redirected() = false, want true: another URL answered for the published one")
	}
	ev := s.Verify(netip.MustParseAddr("203.0.113.7"), "ExampleBot", fetched.Add(time.Hour))
	if ev.Kind != EvidenceRange {
		t.Errorf("kind = %v, want %v: a redirect flags the source, it does not void the match", ev.Kind, EvidenceRange)
	}
	if ev.Detail != s.FinalURL {
		t.Errorf("detail = %q, want the URL that answered %q", ev.Detail, s.FinalURL)
	}
	got := reasonMessage(ev.Reasons, ReasonSnapshotRedirected)
	if got == "" {
		t.Fatalf("reasons = %+v, want a %q reason", ev.Reasons, ReasonSnapshotRedirected)
	}
	if !strings.Contains(got, s.URL) || !strings.Contains(got, s.FinalURL) {
		t.Errorf("message = %q, want both the published URL and the one that answered", got)
	}
}

func TestVerifyFileWithoutCreationTime(t *testing.T) {
	s := load(t, Snapshot{
		Operator:  "OpenAI",
		Tokens:    []string{"GPTBot"},
		URL:       "https://openai.com/gptbot.json",
		FetchedAt: fetched,
		Prefixes:  prefixes(t, "203.0.113.0/24"),
	})
	ev := s.Verify(netip.MustParseAddr("203.0.113.7"), "GPTBot", fetched.Add(time.Hour))
	if ev.Kind != EvidenceRange {
		t.Errorf("kind = %v, want %v: a missing creationTime is reported, not disqualifying", ev.Kind, EvidenceRange)
	}
	if !hasReason(ev.Reasons, ReasonNoCreationTime) {
		t.Errorf("reasons = %+v, want a %q reason", ev.Reasons, ReasonNoCreationTime)
	}
}

func TestVerifySharedFileProvesTheOperator(t *testing.T) {
	s := load(t, Snapshot{
		Operator:     "Anthropic",
		Tokens:       []string{"ClaudeBot", "Claude-SearchBot", "Claude-User"},
		URL:          "https://claude.com/crawling/bots.json",
		CreationTime: fetched.Add(-time.Hour),
		FetchedAt:    fetched,
		Prefixes:     prefixes(t, "203.0.113.0/24"),
	})
	ev := s.Verify(netip.MustParseAddr("203.0.113.7"), "ClaudeBot", fetched.Add(time.Hour))
	if ev.Kind != EvidenceRange {
		t.Fatalf("kind = %v, want %v", ev.Kind, EvidenceRange)
	}
	got := reasonMessage(ev.Reasons, ReasonOperatorOnly)
	if got == "" {
		t.Fatalf("reasons = %+v, want a %q reason: one file for several products names no product", ev.Reasons, ReasonOperatorOnly)
	}
	for _, want := range []string{"Anthropic", "ClaudeBot", "Claude-User"} {
		if !strings.Contains(got, want) {
			t.Errorf("message = %q, want it to name %q", got, want)
		}
	}
}

func TestRangeEvidenceAppliesTheVendorGroup(t *testing.T) {
	ev := gptbotSnapshot(t).Verify(netip.MustParseAddr("203.0.113.7"), "GPTBot", fetched.Add(time.Hour))
	v := Decide(gptbotRequest("/public"), rules(t), ev)
	if !v.Verified || v.Group.Token != "gptbot" {
		t.Fatalf("verdict = %+v, want GPTBot verified under its own group", v)
	}
	if !v.Allowed {
		t.Errorf("/public refused, want allowed: %+v", v.Reasons)
	}
	if v.Reasons[0].Kind != ReasonInRange {
		t.Errorf("chain opens with %q, want the range match that settled identity", v.Reasons[0].Kind)
	}
	if !hasReason(v.Reasons, ReasonVerified) {
		t.Errorf("reasons = %+v, want the verification in the chain", v.Reasons)
	}
}

func TestStaleSnapshotLeavesTheRequestAClaimant(t *testing.T) {
	s := gptbotSnapshot(t)
	ev := s.Verify(netip.MustParseAddr("203.0.113.7"), "GPTBot", fetched.Add(DefaultMaxAge+time.Hour))
	v := Decide(gptbotRequest("/public"), rules(t), ev)
	if v.Verified {
		t.Fatalf("verdict = %+v, want unverified: a stale file verifies nothing", v)
	}
	if v.Group.Token != "*" {
		t.Errorf("group = %q, want the * group", v.Group.Token)
	}
	if v.Reasons[0].Kind != ReasonSnapshotStale {
		t.Errorf("chain opens with %q, want %q", v.Reasons[0].Kind, ReasonSnapshotStale)
	}
	if got := reasonMessage(v.Reasons, ReasonClaimed); got != "claimed GPTBot, unverified" {
		t.Errorf("claim reason = %q, want %q", got, "claimed GPTBot, unverified")
	}
	if v.Allowed {
		t.Error("/public allowed, want refused by the * group")
	}
}

type stubResolver struct {
	names   map[string][]string // address to reverse names
	hosts   map[string][]string // host to addresses
	addrErr error
	hostErr error
}

func (r stubResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if r.addrErr != nil {
		return nil, r.addrErr
	}
	return r.names[addr], nil
}

func (r stubResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if r.hostErr != nil {
		return nil, r.hostErr
	}
	addrs, ok := r.hosts[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	return addrs, nil
}

const (
	googlebotAddr = "66.249.66.1"
	googlebotName = "crawl-66-249-66-1.googlebot.com"
)

var googlebotSuffixes = []string{"crawl.googlebot.com", "googlebot.com"}

func TestFCrDNSVerifiesANameThatResolvesBack(t *testing.T) {
	res := stubResolver{
		names: map[string][]string{googlebotAddr: {googlebotName + "."}},
		hosts: map[string][]string{googlebotName: {googlebotAddr}},
	}
	ev := FCrDNS(context.Background(), res, netip.MustParseAddr(googlebotAddr), "Googlebot", googlebotSuffixes)
	if ev.Kind != EvidenceFCrDNS || !ev.Kind.Verifies() {
		t.Fatalf("kind = %v, want %v", ev.Kind, EvidenceFCrDNS)
	}
	if ev.Detail != googlebotName {
		t.Errorf("detail = %q, want the reverse name %q", ev.Detail, googlebotName)
	}
	got := reasonMessage(ev.Reasons, ReasonFCrDNS)
	if got == "" {
		t.Fatalf("reasons = %+v, want a %q reason", ev.Reasons, ReasonFCrDNS)
	}
	if !strings.Contains(got, googlebotAddr) || !strings.Contains(got, googlebotName) {
		t.Errorf("message = %q, want the address and the name it reverses to", got)
	}
}

func TestFCrDNSRefusesANameOutsideThePublishedSuffixes(t *testing.T) {
	res := stubResolver{
		names: map[string][]string{googlebotAddr: {"node-1.example.net."}},
		hosts: map[string][]string{"node-1.example.net": {googlebotAddr}},
	}
	ev := FCrDNS(context.Background(), res, netip.MustParseAddr(googlebotAddr), "Googlebot", googlebotSuffixes)
	if ev.Kind.Verifies() {
		t.Fatalf("kind = %v, want nothing verified", ev.Kind)
	}
	got := reasonMessage(ev.Reasons, ReasonReverseSuffix)
	if got == "" {
		t.Fatalf("reasons = %+v, want a %q reason", ev.Reasons, ReasonReverseSuffix)
	}
	if !strings.Contains(got, "node-1.example.net") || !strings.Contains(got, "googlebot.com") {
		t.Errorf("message = %q, want the name found and the suffixes expected", got)
	}
}

func TestFCrDNSRefusesANameThatDoesNotResolveBack(t *testing.T) {
	res := stubResolver{
		names: map[string][]string{googlebotAddr: {googlebotName + "."}},
		hosts: map[string][]string{googlebotName: {"198.51.100.4"}},
	}
	ev := FCrDNS(context.Background(), res, netip.MustParseAddr(googlebotAddr), "Googlebot", googlebotSuffixes)
	if ev.Kind.Verifies() {
		t.Fatalf("kind = %v, want nothing verified: the name has to resolve back", ev.Kind)
	}
	if !hasReason(ev.Reasons, ReasonForwardMismatch) {
		t.Errorf("reasons = %+v, want a %q reason", ev.Reasons, ReasonForwardMismatch)
	}
	if hasReason(ev.Reasons, ReasonReverseSuffix) {
		t.Errorf("reasons = %+v, want no %q reason: the suffix was right, the forward lookup was not", ev.Reasons, ReasonReverseSuffix)
	}
}

func TestFCrDNSAddressWithNoReverseName(t *testing.T) {
	ev := FCrDNS(context.Background(), stubResolver{}, netip.MustParseAddr("198.51.100.4"), "Googlebot", googlebotSuffixes)
	if ev.Kind.Verifies() {
		t.Fatalf("kind = %v, want nothing verified", ev.Kind)
	}
	if !hasReason(ev.Reasons, ReasonNoReverseName) {
		t.Errorf("reasons = %+v, want a %q reason", ev.Reasons, ReasonNoReverseName)
	}
}

func TestFCrDNSResolverFailureIsHeldAgainstNobody(t *testing.T) {
	cases := []struct {
		name string
		res  stubResolver
	}{
		{"the reverse lookup fails", stubResolver{addrErr: errors.New("server misbehaving")}},
		{
			name: "the forward lookup fails",
			res: stubResolver{
				names:   map[string][]string{googlebotAddr: {googlebotName + "."}},
				hostErr: errors.New("i/o timeout"),
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := FCrDNS(context.Background(), c.res, netip.MustParseAddr(googlebotAddr), "Googlebot", googlebotSuffixes)
			if ev.Kind.Verifies() {
				t.Fatalf("kind = %v, want nothing verified", ev.Kind)
			}
			if !hasReason(ev.Reasons, ReasonResolver) {
				t.Fatalf("reasons = %+v, want a %q reason: a resolver that fails disproves nothing", ev.Reasons, ReasonResolver)
			}
			for _, kind := range []string{ReasonForwardMismatch, ReasonNoReverseName} {
				if hasReason(ev.Reasons, kind) {
					t.Errorf("reasons = %+v, want no %q reason", ev.Reasons, kind)
				}
			}
		})
	}
}

func TestFCrDNSEvidenceNamesTheClaimItContradicts(t *testing.T) {
	res := stubResolver{
		names: map[string][]string{googlebotAddr: {googlebotName + "."}},
		hosts: map[string][]string{googlebotName: {googlebotAddr}},
	}
	ev := FCrDNS(context.Background(), res, netip.MustParseAddr(googlebotAddr), "Googlebot", googlebotSuffixes)
	v := Decide(gptbotRequest("/public"), rules(t), ev)
	if !v.Verified || v.Token != "Googlebot" {
		t.Fatalf("verdict = %+v, want Googlebot verified: the evidence decides the token, not the header", v)
	}
	if v.Claimed != "GPTBot" {
		t.Errorf("claimed = %q, want the GPTBot the header named", v.Claimed)
	}
	got := reasonMessage(v.Reasons, ReasonTokenMismatch)
	if got == "" {
		t.Fatalf("reasons = %+v, want a %q reason", v.Reasons, ReasonTokenMismatch)
	}
	if !strings.Contains(got, "GPTBot") || !strings.Contains(got, "Googlebot") {
		t.Errorf("message = %q, want both the claimed and the verified token", got)
	}
	if v.Group.Token != "*" {
		t.Errorf("group = %q, want the * group: the file names no group for Googlebot", v.Group.Token)
	}
}
