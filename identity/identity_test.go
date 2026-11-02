package identity

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/polycratia/crawlwarrant/robots"
)

const siteRobots = `User-agent: GPTBot
Disallow: /private

User-agent: *
Disallow: /
`

func rules(t *testing.T) robots.Policy {
	t.Helper()
	p := robots.FromFetch(robots.Outcome{Status: 200, Body: []byte(siteRobots)})
	if p.Effect != robots.EffectRules {
		t.Fatalf("policy effect = %v, want %v", p.Effect, robots.EffectRules)
	}
	return p
}

func gptbotRequest(path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)")
	return r
}

func hasReason(reasons []Reason, kind string) bool {
	for _, r := range reasons {
		if r.Kind == kind {
			return true
		}
	}
	return false
}

func reasonMessage(reasons []Reason, kind string) string {
	for _, r := range reasons {
		if r.Kind == kind {
			return r.Message
		}
	}
	return ""
}

func TestVerifiedEvidenceAppliesTheVendorGroup(t *testing.T) {
	v := Decide(gptbotRequest("/public"), rules(t), Signed("GPTBot", "https://chatgpt.com/.well-known/http-message-signatures-directory"))
	if !v.Verified || v.Token != "GPTBot" {
		t.Fatalf("verdict = %+v, want GPTBot verified", v)
	}
	if v.Group.Token != "gptbot" {
		t.Errorf("group = %q, want %q: evidence puts the vendor's group in force", v.Group.Token, "gptbot")
	}
	if !v.Allowed {
		t.Errorf("/public refused, want allowed: %+v", v.Reasons)
	}
	if !hasReason(v.Reasons, ReasonSigned) || !hasReason(v.Reasons, ReasonVerified) {
		t.Errorf("reasons = %+v, want the signature and the verification in the chain", v.Reasons)
	}
}

func TestVerifiedGroupStillRefusesItsOwnDisallow(t *testing.T) {
	v := Decide(gptbotRequest("/private/page"), rules(t), Signed("GPTBot", "https://example.com/directory"))
	if v.Allowed {
		t.Fatalf("/private/page allowed, want refused: %+v", v.Reasons)
	}
	if v.Rule.Kind != robots.Disallow || v.Rule.Line != 2 {
		t.Errorf("deciding rule = %+v, want the disallow on line 2", v.Rule)
	}
}

func TestKnownTokenWithoutEvidenceIsAClaimant(t *testing.T) {
	v := Decide(gptbotRequest("/public"), rules(t), Evidence{})
	if v.Verified {
		t.Fatalf("verdict = %+v, want unverified: a token in a header proves nothing", v)
	}
	if v.Token != "GPTBot" || v.Claimed != "GPTBot" {
		t.Errorf("token = %q, claimed = %q, want GPTBot both", v.Token, v.Claimed)
	}
	if v.Group.Token != "*" {
		t.Errorf("group = %q, want the * group: an unverified claim never puts a vendor's group in force", v.Group.Token)
	}
	if got := reasonMessage(v.Reasons, ReasonClaimed); got != "claimed GPTBot, unverified" {
		t.Errorf("claim reason = %q, want %q", got, "claimed GPTBot, unverified")
	}
	if v.Allowed {
		t.Errorf("/public allowed, want refused: the * group disallows everything")
	}
}

func TestAnonymousRequestGetsTheStarGroup(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/public", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
	v := Decide(r, rules(t), Evidence{})
	if v.Token != "" || v.Claimed != "" {
		t.Errorf("verdict = %+v, want no token claimed", v)
	}
	if v.Group.Token != "*" || !hasReason(v.Reasons, ReasonAnonymous) {
		t.Errorf("group = %q, reasons = %+v, want the * group and an anonymous reason", v.Group.Token, v.Reasons)
	}
}

func TestClaimMatchesWholeTokensOnly(t *testing.T) {
	cases := []struct {
		ua   string
		want string
	}{
		{"Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)", "GPTBot"},
		{"Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)", "ChatGPT-User"},
		{"bingbot/2.0", "bingbot"},
		{"MyGPTBotClone/1.0", ""},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", ""},
	}
	for _, c := range cases {
		got, ok := Claim(c.ua)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("Claim(%q) = %q (ok %v), want %q", c.ua, got, ok, c.want)
		}
	}
}

func TestFetchStatusDecidesWithoutRules(t *testing.T) {
	cases := []struct {
		status  int
		allowed bool
	}{{404, true}, {503, false}}
	for _, c := range cases {
		v := Decide(gptbotRequest("/anything"), robots.FromFetch(robots.Outcome{Status: c.status}), Signed("GPTBot", "https://example.com/directory"))
		if v.Allowed != c.allowed {
			t.Errorf("status %d allowed = %v, want %v", c.status, v.Allowed, c.allowed)
		}
		if !hasReason(v.Reasons, ReasonEffect) {
			t.Errorf("status %d reasons = %+v, want the status in the chain", c.status, v.Reasons)
		}
	}
}

func TestDivergentStatusIsUndecidedUntilAReadingIsPicked(t *testing.T) {
	p := robots.FromFetch(robots.Outcome{Status: 429})
	ev := Signed("GPTBot", "https://example.com/directory")
	v := Decide(gptbotRequest("/a"), p, ev)
	if v.Allowed || !hasReason(v.Reasons, ReasonUndecided) {
		t.Fatalf("verdict = %+v, want a refusal that names the undecided policy", v)
	}
	under, err := p.Under(robots.ReadingRFC9309)
	if err != nil {
		t.Fatalf("Under: %v", err)
	}
	if v := Decide(gptbotRequest("/a"), under, ev); !v.Allowed {
		t.Errorf("verdict under rfc9309 = %+v, want allowed", v)
	}
}

func TestMiddlewareRecordsAndBlocksOnlyWithEnforce(t *testing.T) {
	var served bool
	var got Verdict
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served = true
		v, ok := FromContext(r.Context())
		if !ok {
			t.Error("no verdict in the request context")
		}
		got = v
	})
	opts := Options{Policy: rules(t)}

	rec := httptest.NewRecorder()
	Middleware(next, opts).ServeHTTP(rec, gptbotRequest("/public"))
	if !served || rec.Code != http.StatusOK {
		t.Fatalf("served = %v, status = %d, want a served request without Enforce", served, rec.Code)
	}
	if got.Allowed || got.Group.Token != "*" {
		t.Errorf("verdict = %+v, want the unverified claim refused by the * group but still served", got)
	}

	served = false
	opts.Enforce = true
	rec = httptest.NewRecorder()
	Middleware(next, opts).ServeHTTP(rec, gptbotRequest("/public"))
	if served {
		t.Error("a refused request reached the handler with Enforce set")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	served = false
	opts.Evidence = func(*http.Request) Evidence { return Signed("GPTBot", "https://example.com/directory") }
	rec = httptest.NewRecorder()
	Middleware(next, opts).ServeHTTP(rec, gptbotRequest("/public"))
	if !served || rec.Code != http.StatusOK {
		t.Errorf("served = %v, status = %d, want a verified request served under Enforce", served, rec.Code)
	}
}

func TestEvidenceKindVerifies(t *testing.T) {
	cases := []struct {
		kind EvidenceKind
		want bool
		text string
	}{
		{EvidenceSigned, true, "signed"},
		{EvidenceRange, true, "range"},
		{EvidenceFCrDNS, true, "fcrdns"},
		{EvidenceClaimant, false, "claimant"},
		{EvidenceAnonymous, false, "anonymous"},
	}
	for _, c := range cases {
		if got := c.kind.Verifies(); got != c.want {
			t.Errorf("%v.Verifies() = %v, want %v", c.kind, got, c.want)
		}
		if got := c.kind.String(); got != c.text {
			t.Errorf("EvidenceKind(%d) = %q, want %q", c.kind, got, c.text)
		}
	}
}

func TestClaimedEvidenceStaysAClaim(t *testing.T) {
	v := Decide(gptbotRequest("/public"), rules(t), Claimed("GPTBot"))
	if v.Verified || v.Group.Token != "*" {
		t.Errorf("verdict = %+v, want an unverified claim under the * group", v)
	}
}
