// Package identity settles who a request is before it applies what a site
// allowed: a vendor's robots.txt group governs a request only when evidence
// ties the request to that vendor, and a request that merely names a product
// token is a claimant, governed by the * group. Every verdict is the ordered
// chain of reasons that produced it.
package identity

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/polycratia/crawlwarrant/purpose"
	"github.com/polycratia/crawlwarrant/robots"
)

// EvidenceKind is what ties a request to the operator of a product token.
type EvidenceKind uint8

const (
	// EvidenceAnonymous is the zero kind: the request names no published token
	// and nothing ties it to an operator.
	EvidenceAnonymous EvidenceKind = iota
	// EvidenceSigned is an HTTP message signature the caller verified against
	// the key directory the operator publishes.
	EvidenceSigned
	// EvidenceRange is a client address inside a fresh range snapshot.
	EvidenceRange
	// EvidenceFCrDNS is forward-confirmed reverse DNS.
	EvidenceFCrDNS
	// EvidenceClaimant is a request that names a published token and proves
	// nothing: evidence of a claim, not of an identity.
	EvidenceClaimant
)

func (k EvidenceKind) String() string {
	switch k {
	case EvidenceSigned:
		return "signed"
	case EvidenceRange:
		return "range"
	case EvidenceFCrDNS:
		return "fcrdns"
	case EvidenceClaimant:
		return "claimant"
	}
	return "anonymous"
}

// Verifies reports whether the kind ties a request to an operator. Signed,
// range and fcrdns do; a claimant and an anonymous request prove nothing, so no
// vendor's group ever applies to them.
func (k EvidenceKind) Verifies() bool {
	switch k {
	case EvidenceSigned, EvidenceRange, EvidenceFCrDNS:
		return true
	}
	return false
}

// Kinds of Reason, in the order a chain carries them: how identity was
// settled, which group that put in force, then what decided the path.
const (
	ReasonSigned             = "signature verified"
	ReasonInRange            = "address in published range"
	ReasonOutOfRange         = "address outside published range"
	ReasonSnapshotStale      = "range snapshot stale"
	ReasonSnapshotRedirected = "range source redirected"
	ReasonNoCreationTime     = "range file has no creation time"
	ReasonOperatorOnly       = "range file shared by several tokens"
	ReasonFCrDNS             = "forward-confirmed reverse dns"
	ReasonNoReverseName      = "address has no reverse name"
	ReasonReverseSuffix      = "reverse name outside published suffixes"
	ReasonForwardMismatch    = "reverse name does not resolve back"
	ReasonResolver           = "resolver failed"
	ReasonVerified           = "identity verified"
	ReasonTokenMismatch      = "claimed token is not the verified one"
	ReasonClaimed            = "claimed token"
	ReasonAnonymous          = "no published token claimed"
	ReasonGroup              = "group applied"
	ReasonRule               = "rule decided"
	ReasonNoRule             = "no rule matched"
	ReasonEffect             = "fetch status decided"
	ReasonUndecided          = "policy undecided"
)

// Reason is one step of a chain, in the order it was taken.
type Reason struct {
	Kind    string // one of the Reason constants above
	Message string
}

// Evidence is what a caller established about a request before any policy was
// read. Reasons is how it was established, or why it was not, and it opens the
// chain of the Verdict.
type Evidence struct {
	Kind     EvidenceKind
	Token    string // product token the evidence is about
	Operator string // operator it ties the request to, when known
	Detail   string // URL or host the evidence came from
	Reasons  []Reason
}

// Signed records a signature the caller already verified against the key
// directory at agent. This package verifies no signatures; it records that a
// caller did, so the chain can say so.
func Signed(token, agent string) Evidence {
	return Evidence{
		Kind:   EvidenceSigned,
		Token:  token,
		Detail: agent,
		Reasons: []Reason{{
			Kind:    ReasonSigned,
			Message: fmt.Sprintf("the request signature was verified against the key directory at %s", agent),
		}},
	}
}

// Claimed records a request that names a product token and proves nothing
// further. Decide reaches the same state on its own from the User-Agent.
func Claimed(token string) Evidence {
	return Evidence{Kind: EvidenceClaimant, Token: token}
}

// Claim returns the published product token a User-Agent header names, spelled
// as the purpose table spells it. A token is matched as a whole, never as a
// substring of a longer word, and the longest token the header names wins.
func Claim(userAgent string) (string, bool) {
	var best string
	for _, row := range purpose.Table {
		if len(row.Token) > len(best) && namesToken(userAgent, row.Token) {
			best = row.Token
		}
	}
	return best, best != ""
}

func namesToken(userAgent, token string) bool {
	haystack, want := strings.ToLower(userAgent), strings.ToLower(token)
	if want == "" {
		return false
	}
	for from := 0; from+len(want) <= len(haystack); {
		i := strings.Index(haystack[from:], want)
		if i < 0 {
			return false
		}
		start, end := from+i, from+i+len(want)
		before := start == 0 || !isTokenByte(haystack[start-1])
		after := end == len(haystack) || !isTokenByte(haystack[end])
		if before && after {
			return true
		}
		from = start + 1
	}
	return false
}

func isTokenByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return c == '-' || c == '_'
}

// Resolver is the DNS an identity check uses. *net.Resolver satisfies it, and
// a test supplies its own, so no test touches live DNS.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// FCrDNS verifies an address by forward-confirmed reverse DNS: it must reverse
// to a name inside one of the published suffixes, and that name must resolve
// back to it. A resolver that fails verifies nothing and is held against
// nobody: the failure travels as a reason.
func FCrDNS(ctx context.Context, res Resolver, ip netip.Addr, token string, suffixes []string) Evidence {
	e := Evidence{Token: token}
	names, err := res.LookupAddr(ctx, ip.String())
	if err != nil {
		e.Reasons = append(e.Reasons, Reason{ReasonResolver, fmt.Sprintf("the reverse lookup of %s failed (%v): nothing is verified", ip, err)})
		return e
	}
	if len(names) == 0 {
		e.Reasons = append(e.Reasons, Reason{ReasonNoReverseName, fmt.Sprintf("%s has no reverse name", ip)})
		return e
	}
	for _, name := range names {
		host := strings.TrimSuffix(strings.ToLower(name), ".")
		if !hasDNSSuffix(host, suffixes) {
			continue
		}
		addrs, err := res.LookupHost(ctx, host)
		if err != nil {
			e.Reasons = append(e.Reasons, Reason{ReasonResolver, fmt.Sprintf("the forward lookup of %s failed (%v): nothing is verified", host, err)})
			continue
		}
		if !containsAddr(addrs, ip) {
			e.Reasons = append(e.Reasons, Reason{ReasonForwardMismatch, fmt.Sprintf("%s reverses to %s, but %s resolves to %s and not back to it", ip, host, host, strings.Join(addrs, ", "))})
			continue
		}
		e.Kind, e.Detail = EvidenceFCrDNS, host
		e.Reasons = append(e.Reasons, Reason{ReasonFCrDNS, fmt.Sprintf("%s reverses to %s, inside the published %s, and %s resolves back to %s", ip, host, strings.Join(suffixes, ", "), host, ip)})
		return e
	}
	if len(e.Reasons) == 0 {
		e.Reasons = append(e.Reasons, Reason{ReasonReverseSuffix, fmt.Sprintf("%s reverses to %s, outside the published %s", ip, strings.Join(names, ", "), strings.Join(suffixes, ", "))})
	}
	return e
}

func hasDNSSuffix(host string, suffixes []string) bool {
	for _, s := range suffixes {
		s = strings.ToLower(strings.TrimSuffix(s, "."))
		if s == "" {
			continue
		}
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

func containsAddr(addrs []string, ip netip.Addr) bool {
	for _, a := range addrs {
		got, err := netip.ParseAddr(a)
		if err == nil && got.Unmap() == ip.Unmap() {
			return true
		}
	}
	return false
}

// Verdict is what a request was allowed, and the chain that says why.
type Verdict struct {
	Token    string       // token the verdict is about, verified when Verified
	Claimed  string       // token the User-Agent named, empty when none
	Verified bool         // whether evidence tied the request to the operator
	Group    robots.Group // group that governed the request
	Path     string       // path the rules were matched against
	Rule     robots.Rule  // rule that decided, zero when none did
	Allowed  bool
	Reasons  []Reason
}

// Deciding returns the last reason of the chain, the one that settled the path.
func (v Verdict) Deciding() Reason {
	if len(v.Reasons) == 0 {
		return Reason{}
	}
	return v.Reasons[len(v.Reasons)-1]
}

// Decide reads identity first and policy second. A vendor's group applies only
// when the evidence verifies the token; a request that names a published token
// without evidence is a claimant, gets the * group, and the chain records
// "claimed <token>, unverified". An unverified request is never called an
// impostor: nothing about it was disproved.
func Decide(req *http.Request, policy robots.Policy, ev Evidence) Verdict {
	v := Verdict{Path: requestPath(req), Allowed: true}
	v.Claimed, _ = Claim(req.UserAgent())
	v.Reasons = append(v.Reasons, ev.Reasons...)

	token := ev.Token
	if token == "" {
		token = v.Claimed
	}
	groupToken := "*"
	switch {
	case ev.Kind.Verifies():
		v.Verified, v.Token, groupToken = true, token, token
		if v.Claimed != "" && !strings.EqualFold(v.Claimed, token) {
			v.Reasons = append(v.Reasons, Reason{ReasonTokenMismatch, fmt.Sprintf("the User-Agent claims %s while the evidence verifies %s: the verified token decides", v.Claimed, token)})
		}
		detail := ev.Detail
		if detail == "" {
			detail = "the evidence the caller recorded"
		}
		v.Reasons = append(v.Reasons, Reason{ReasonVerified, fmt.Sprintf("%s is verified by %s evidence (%s): the group naming it applies", token, ev.Kind, detail)})
	case token != "":
		v.Token = token
		v.Reasons = append(v.Reasons, Reason{ReasonClaimed, fmt.Sprintf("claimed %s, unverified", token)})
	default:
		v.Reasons = append(v.Reasons, Reason{ReasonAnonymous, "the request names no published product token: the * group applies"})
	}

	group, ok := policy.File.Select(groupToken)
	v.Group = group
	if ok {
		v.Reasons = append(v.Reasons, Reason{ReasonGroup, fmt.Sprintf("the %q group governs the request", group.Token)})
	} else {
		v.Reasons = append(v.Reasons, Reason{ReasonGroup, "the file names no group for this request and has no * group: every path is allowed"})
	}

	switch policy.Effect {
	case robots.EffectRules:
		if rule, ok := group.Match(v.Path); ok {
			v.Rule, v.Allowed = rule, rule.Kind == robots.Allow
			v.Reasons = append(v.Reasons, Reason{ReasonRule, fmt.Sprintf("%s %q on line %d decides %s for %s", rule.Kind, rule.Pattern, rule.Line, allowed(v.Allowed), v.Path)})
		} else {
			v.Reasons = append(v.Reasons, Reason{ReasonNoRule, fmt.Sprintf("no rule of the group matches %s: it is allowed", v.Path)})
		}
	case robots.EffectAllowAll:
		v.Reasons = append(v.Reasons, Reason{ReasonEffect, policy.Reason})
	case robots.EffectDisallowAll:
		v.Allowed = false
		v.Reasons = append(v.Reasons, Reason{ReasonEffect, policy.Reason})
	default:
		v.Allowed = false
		message := "no policy was read for this site: nothing says what is allowed"
		if policy.Divergence != nil {
			message = fmt.Sprintf("status %d is read differently by its sources: pick a Reading with Policy.Under before deciding", policy.Divergence.Status)
		}
		v.Reasons = append(v.Reasons, Reason{ReasonUndecided, message})
	}
	return v
}

func allowed(ok bool) string {
	if ok {
		return "allowed"
	}
	return "refused"
}

func requestPath(req *http.Request) string {
	if req.URL == nil {
		return "/"
	}
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	if req.URL.RawQuery != "" {
		path += "?" + req.URL.RawQuery
	}
	return path
}

// Options configures Middleware.
type Options struct {
	// Policy is the site's access policy, as robots.FromFetch read it.
	Policy robots.Policy
	// Evidence returns what the caller established about a request. A nil func
	// leaves every request a claimant or anonymous.
	Evidence func(*http.Request) Evidence
	// Enforce answers a refused request with 403. Left unset, every request is
	// served and only the verdict records what the policy said.
	Enforce bool
}

type contextKey struct{}

// FromContext returns the verdict Middleware stored for the request.
func FromContext(ctx context.Context) (Verdict, bool) {
	v, ok := ctx.Value(contextKey{}).(Verdict)
	return v, ok
}

// Middleware decides every request, stores the Verdict in its context for
// FromContext, and blocks with 403 only when opts.Enforce is set.
func Middleware(next http.Handler, opts Options) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev Evidence
		if opts.Evidence != nil {
			ev = opts.Evidence(r)
		}
		v := Decide(r, opts.Policy, ev)
		r = r.WithContext(context.WithValue(r.Context(), contextKey{}, v))
		if opts.Enforce && !v.Allowed {
			http.Error(w, v.Deciding().Message, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
