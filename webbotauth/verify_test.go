package webbotauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	testDirectory = "https://crawler.example/.well-known/http-message-signatures-directory"
	testLabel     = "sig1"
	defaultTarget = "https://site.example/articles/1?page=2"
	// unverifiableBase is what a spec that spells the Signature-Input field out
	// itself signs: those cases are refused before the signature is checked.
	unverifiableBase = "a base no request rebuilds"
)

var (
	testNow     = time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)
	testCreated = testNow.Add(-30 * time.Second)
	testExpires = testNow.Add(5 * time.Minute)
)

type testKey struct {
	priv ed25519.PrivateKey
	jwk  JWK
}

func newKey(t *testing.T) testKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return testKey{priv: priv, jwk: JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}}
}

// fixture is a keyring holding one key generated here, published by
// testDirectory, with the thumbprint it was recorded under.
type fixture struct {
	keys       *Keyring
	key        testKey
	thumbprint string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	k := newKey(t)
	ring := NewKeyring()
	thumbprint, err := ring.Add(testDirectory, k.jwk)
	if err != nil {
		t.Fatalf("Keyring.Add: %v", err)
	}
	return fixture{keys: ring, key: k, thumbprint: thumbprint}
}

// spec returns a request that verifies, so a case can change one thing about
// it and leave the rest well-formed.
func (f fixture) spec() spec {
	return spec{
		label:      testLabel,
		components: []string{"@authority", "signature-agent"},
		params:     sigParams(f.thumbprint, testCreated, testExpires),
		key:        f.key.priv,
	}
}

// spec is one request to sign: the fields it carries, what the signature
// covers, and the key that signs it.
type spec struct {
	headers     map[string]string
	agent       string // Signature-Agent field, the dictionary form by default
	noAgent     bool
	label       string
	components  []string // nil when rawInput spells the covered components out
	params      string
	rawInput    string // whole Signature-Input field
	noInput     bool
	noSignature bool
	key         ed25519.PrivateKey
	tamper      func(*http.Request)
}

func (s spec) build(t *testing.T) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, defaultTarget, nil)
	r.Header.Set("User-Agent", "ExampleBot/1.0")
	for name, value := range s.headers {
		r.Header.Set(name, value)
	}
	if !s.noAgent {
		field := s.agent
		if field == "" {
			field = fmt.Sprintf("%s=%q", s.label, testDirectory)
		}
		r.Header.Set("Signature-Agent", field)
	}
	if !s.noInput {
		input := s.rawInput
		if input == "" {
			input = s.label + "=(" + strings.Join(quoted(s.components), " ") + ")" + s.params
		}
		r.Header.Set("Signature-Input", input)
	}
	if !s.noSignature {
		base := unverifiableBase
		if s.components != nil {
			base = wantBase(r, s.components, s.params)
		}
		r.Header.Set("Signature", s.label+"=:"+base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, []byte(base)))+":")
	}
	if s.tamper != nil {
		s.tamper(r)
	}
	return r
}

func sigParams(thumbprint string, created, expires time.Time) string {
	return fmt.Sprintf(`;created=%d;expires=%d;keyid=%q;tag=%q`, created.Unix(), expires.Unix(), thumbprint, Tag)
}

func quoted(names []string) []string {
	out := make([]string, len(names))
	for i, name := range names {
		out[i] = `"` + name + `"`
	}
	return out
}

// wantBase spells the RFC 9421 signature base out here rather than calling the
// package, so a signature made in the test verifies only if Verify rebuilds
// the same bytes from the request itself.
func wantBase(r *http.Request, components []string, params string) string {
	var b strings.Builder
	for _, name := range components {
		b.WriteString(`"` + name + `": ` + componentForTest(r, name) + "\n")
	}
	b.WriteString(`"@signature-params": (` + strings.Join(quoted(components), " ") + ")" + params)
	return b.String()
}

func componentForTest(r *http.Request, name string) string {
	authority := strings.TrimSuffix(strings.ToLower(r.Host), ":443")
	switch name {
	case "@method":
		return r.Method
	case "@authority":
		return authority
	case "@scheme":
		return r.URL.Scheme
	case "@path":
		return r.URL.EscapedPath()
	case "@query":
		return "?" + r.URL.RawQuery
	case "@target-uri":
		target := r.URL.Scheme + "://" + authority + r.URL.EscapedPath()
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		return target
	}
	return strings.TrimSpace(r.Header.Get(name))
}

func reasonKinds(reasons []Reason) []string {
	kinds := make([]string, len(reasons))
	for i, reason := range reasons {
		kinds[i] = reason.Kind
	}
	return kinds
}

func hasReason(reasons []Reason, kind string) bool {
	for _, reason := range reasons {
		if reason.Kind == kind {
			return true
		}
	}
	return false
}

type memoryCache struct{ seen map[string]time.Time }

func (c *memoryCache) Seen(key string, expires time.Time) bool {
	if _, ok := c.seen[key]; ok {
		return true
	}
	if c.seen == nil {
		c.seen = make(map[string]time.Time)
	}
	c.seen[key] = expires
	return false
}

func TestVerifySignedRequest(t *testing.T) {
	f := newFixture(t)
	s := f.spec()
	s.components = []string{"@method", "@authority", "@path", "@query", "@target-uri", "signature-agent", "user-agent"}
	r := s.build(t)

	v, err := Verify(r, f.keys, testNow)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.Label != testLabel || v.Directory != testDirectory || v.Thumbprint != f.thumbprint {
		t.Errorf("verdict = %+v, want the label, the directory and the thumbprint %q", v, f.thumbprint)
	}
	if !reflect.DeepEqual(v.Components, s.components) {
		t.Errorf("components = %v, want %v, in the order the field gave them", v.Components, s.components)
	}
	if want := wantBase(r, s.components, s.params); v.Base != want {
		t.Errorf("base =\n%q\nwant\n%q", v.Base, want)
	}
	if !v.Created.Equal(testCreated) || !v.Expires.Equal(testExpires) {
		t.Errorf("window = %s to %s, want %s to %s", v.Created, v.Expires, testCreated, testExpires)
	}
	if v.Nonce != "" {
		t.Errorf("nonce = %q, want none: the signature carried none", v.Nonce)
	}
	if len(v.Reasons) != 1 || v.Reasons[0].Kind != ReasonReplayable || v.Reasons[0].Message == "" {
		t.Errorf("reasons = %+v, want only %q with a message: nothing stops the signature being sent again", v.Reasons, ReasonReplayable)
	}
}

func TestVerifyPicksTheWebBotAuthSignature(t *testing.T) {
	f := newFixture(t)
	s := f.spec()
	s.label = "wba"
	s.agent = fmt.Sprintf(`other="https://elsewhere.example/keys", wba=%q`, testDirectory)
	s.rawInput = fmt.Sprintf(`other=("@method");created=%d;tag="another-protocol", wba=(%s)%s`,
		testCreated.Unix(), strings.Join(quoted(s.components), " "), s.params)

	v, err := Verify(s.build(t), f.keys, testNow)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.Label != "wba" {
		t.Errorf("label = %q, want wba: the signature tagged %s is the one to verify", v.Label, Tag)
	}
}

func TestVerifyLegacySignatureAgent(t *testing.T) {
	f := newFixture(t)
	s := f.spec()
	s.agent = fmt.Sprintf("%q", testDirectory)

	v, err := Verify(s.build(t), f.keys, testNow)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.Directory != testDirectory {
		t.Errorf("directory = %q, want %q", v.Directory, testDirectory)
	}
	if !hasReason(v.Reasons, ReasonLegacyAgent) {
		t.Errorf("reasons = %v, want a %q reason: the bare string form is read, never produced", reasonKinds(v.Reasons), ReasonLegacyAgent)
	}
}

func TestVerifyReportsALongLifetime(t *testing.T) {
	f := newFixture(t)
	s := f.spec()
	s.params = sigParams(f.thumbprint, testNow.Add(-time.Hour), testNow.Add(30*time.Hour))

	v, err := Verify(s.build(t), f.keys, testNow)
	if err != nil {
		t.Fatalf("Verify: %v, want a lifetime above %v reported, not refused", err, MaxLifetime)
	}
	if !hasReason(v.Reasons, ReasonLongLifetime) {
		t.Fatalf("reasons = %v, want a %q reason", reasonKinds(v.Reasons), ReasonLongLifetime)
	}
	for _, reason := range v.Reasons {
		if reason.Kind == ReasonLongLifetime && !strings.Contains(reason.Message, Draft) {
			t.Errorf("message = %q, want it to name %s", reason.Message, Draft)
		}
	}
}

func TestVerifyReplayCache(t *testing.T) {
	cases := []struct {
		name  string
		nonce string
	}{
		{"keyed by the nonce", `;nonce="e8N7S2MFd/qrd6T2R3tdfA"`},
		{"keyed by the signature when there is no nonce", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			f.keys.ReplayCache = &memoryCache{}
			s := f.spec()
			s.params += c.nonce

			v, err := Verify(s.build(t), f.keys, testNow)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if hasReason(v.Reasons, ReasonReplayable) {
				t.Errorf("reasons = %v, want no %q reason: a cache is configured", reasonKinds(v.Reasons), ReasonReplayable)
			}
			if c.nonce != "" && v.Nonce == "" {
				t.Error("the verdict carries no nonce, want the one the signature gave")
			}
			if _, err := Verify(s.build(t), f.keys, testNow); !errors.Is(err, ErrReplay) {
				t.Errorf("second Verify error = %v, want %v", err, ErrReplay)
			}
		})
	}
}

func TestVerifyClockSkew(t *testing.T) {
	cases := []struct {
		name    string
		skew    time.Duration
		created time.Time
		expires time.Time
		wantErr bool
	}{
		{"created a little ahead of the verifier", 0, testNow.Add(3 * time.Second), testNow.Add(time.Minute), false},
		{"created past the default skew", 0, testNow.Add(30 * time.Second), testNow.Add(time.Minute), true},
		{"created past a skew the keyring widened", time.Minute, testNow.Add(30 * time.Second), testNow.Add(2 * time.Minute), false},
		{"expired a little before the verifier", 0, testNow.Add(-time.Minute), testNow.Add(-3 * time.Second), false},
		{"expired past the default skew", 0, testNow.Add(-time.Minute), testNow.Add(-30 * time.Second), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			f.keys.Skew = c.skew
			s := f.spec()
			s.params = sigParams(f.thumbprint, c.created, c.expires)

			_, err := Verify(s.build(t), f.keys, testNow)
			if c.wantErr {
				if !errors.Is(err, ErrOutsideWindow) {
					t.Errorf("error = %v, want %v", err, ErrOutsideWindow)
				}
				return
			}
			if err != nil {
				t.Errorf("Verify: %v, want the signature read inside the %v of skew allowed", err, f.keys.skew())
			}
		})
	}
}

func TestVerifyNeedsAKeyring(t *testing.T) {
	f := newFixture(t)
	if _, err := Verify(f.spec().build(t), nil, testNow); err == nil {
		t.Error("Verify with no keyring = no error, want a refusal: there is nothing to verify against")
	}
}

func TestVerifyRefusesAKeyAnotherDirectoryPublished(t *testing.T) {
	f := newFixture(t)
	elsewhere := NewKeyring()
	if _, err := elsewhere.Add("https://elsewhere.example/directory", f.key.jwk); err != nil {
		t.Fatalf("Keyring.Add: %v", err)
	}
	if _, err := Verify(f.spec().build(t), elsewhere, testNow); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("error = %v, want %v: a key proves nothing about a directory that did not publish it", err, ErrUnknownKey)
	}
}

func TestVerifyRefusals(t *testing.T) {
	window := func(created, expires time.Time, extra string) string {
		return fmt.Sprintf(`;created=%d;expires=%d`, created.Unix(), expires.Unix()) + extra
	}
	cases := []struct {
		name string
		want error
		on   func(t *testing.T, s *spec, f fixture)
	}{
		{"no Signature-Input field", ErrNoSignature, func(t *testing.T, s *spec, f fixture) {
			s.noInput = true
		}},
		{"a signature tagged for another protocol", ErrTag, func(t *testing.T, s *spec, f fixture) {
			s.params = window(testCreated, testExpires, fmt.Sprintf(`;keyid=%q;tag="another-protocol"`, f.thumbprint))
		}},
		{"a signature with no tag", ErrTag, func(t *testing.T, s *spec, f fixture) {
			s.params = window(testCreated, testExpires, fmt.Sprintf(`;keyid=%q`, f.thumbprint))
		}},
		{"no Signature field", ErrNoSignature, func(t *testing.T, s *spec, f fixture) {
			s.noSignature = true
		}},
		{"a Signature holding nothing for the label", ErrNoSignature, func(t *testing.T, s *spec, f fixture) {
			s.tamper = func(r *http.Request) {
				r.Header.Set("Signature", strings.Replace(r.Header.Get("Signature"), testLabel+"=", "other=", 1))
			}
		}},
		{"a Signature that is not a byte sequence", ErrNoSignature, func(t *testing.T, s *spec, f fixture) {
			s.tamper = func(r *http.Request) { r.Header.Set("Signature", testLabel+`="not bytes"`) }
		}},
		{"a signature that is not 64 bytes", ErrAlgorithm, func(t *testing.T, s *spec, f fixture) {
			s.tamper = func(r *http.Request) { r.Header.Set("Signature", testLabel+"=:aGk=:") }
		}},
		{"no Signature-Agent field", ErrNoAgent, func(t *testing.T, s *spec, f fixture) {
			s.noAgent = true
		}},
		{"a Signature-Agent naming another label", ErrNoAgent, func(t *testing.T, s *spec, f fixture) {
			s.agent = fmt.Sprintf("other=%q", testDirectory)
		}},
		{"a key directory over http", ErrNotHTTPS, func(t *testing.T, s *spec, f fixture) {
			s.agent = fmt.Sprintf("%s=%q", testLabel, "http://crawler.example/directory")
		}},
		{"neither @authority nor @target-uri covered", ErrCoveredComponents, func(t *testing.T, s *spec, f fixture) {
			s.components = []string{"@method", "signature-agent"}
		}},
		{"signature-agent not covered", ErrCoveredComponents, func(t *testing.T, s *spec, f fixture) {
			s.components = []string{"@authority", "@method"}
		}},
		{"a covered field the request does not carry", ErrCoveredComponents, func(t *testing.T, s *spec, f fixture) {
			s.components = []string{"@authority", "signature-agent", "content-digest"}
		}},
		{"a covered component this package does not rebuild", ErrUnsupportedComponent, func(t *testing.T, s *spec, f fixture) {
			s.rawInput = testLabel + `=("@authority" "signature-agent" "@status")` + s.params
			s.components = nil
		}},
		{"a covered component carrying a parameter", ErrUnsupportedComponent, func(t *testing.T, s *spec, f fixture) {
			s.rawInput = testLabel + `=("@authority" "signature-agent" "content-digest";sf)` + s.params
			s.components = nil
		}},
		{"no created", ErrMissingParameter, func(t *testing.T, s *spec, f fixture) {
			s.params = fmt.Sprintf(`;expires=%d;keyid=%q;tag=%q`, testExpires.Unix(), f.thumbprint, Tag)
		}},
		{"no expires", ErrMissingParameter, func(t *testing.T, s *spec, f fixture) {
			s.params = fmt.Sprintf(`;created=%d;keyid=%q;tag=%q`, testCreated.Unix(), f.thumbprint, Tag)
		}},
		{"no keyid", ErrMissingParameter, func(t *testing.T, s *spec, f fixture) {
			s.params = window(testCreated, testExpires, fmt.Sprintf(`;tag=%q`, Tag))
		}},
		{"expires before created", ErrOutsideWindow, func(t *testing.T, s *spec, f fixture) {
			s.params = sigParams(f.thumbprint, testNow.Add(-time.Minute), testNow.Add(-2*time.Minute))
		}},
		{"a signature claiming HMAC", ErrAlgorithm, func(t *testing.T, s *spec, f fixture) {
			s.params += `;alg="hmac-sha256"`
		}},
		{"an alg that is not a string", ErrAlgorithm, func(t *testing.T, s *spec, f fixture) {
			s.params += `;alg=ed25519`
		}},
		{"a keyid that is not a thumbprint", ErrThumbprintMismatch, func(t *testing.T, s *spec, f fixture) {
			s.params = sigParams("poqkLGiymh_W0uP6PZFw", testCreated, testExpires)
		}},
		{"a thumbprint the directory published no key for", ErrUnknownKey, func(t *testing.T, s *spec, f fixture) {
			other := newKey(t)
			thumbprint, err := other.jwk.Thumbprint()
			if err != nil {
				t.Fatalf("Thumbprint: %v", err)
			}
			s.params = sigParams(thumbprint, testCreated, testExpires)
			s.key = other.priv
		}},
		{"a signature another key made", ErrSignature, func(t *testing.T, s *spec, f fixture) {
			s.key = newKey(t).priv
		}},
		{"a request changed after it was signed", ErrSignature, func(t *testing.T, s *spec, f fixture) {
			s.components = []string{"@authority", "signature-agent", "user-agent"}
			s.tamper = func(r *http.Request) { r.Header.Set("User-Agent", "ImpostorBot/1.0") }
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			s := f.spec()
			c.on(t, &s, f)
			v, err := Verify(s.build(t), f.keys, testNow)
			if err == nil {
				t.Fatalf("Verify = %+v, want a refusal", v)
			}
			if !errors.Is(err, c.want) {
				t.Errorf("error = %v, want it to be %v", err, c.want)
			}
		})
	}
}

func TestThumbprintIsComputedFromTheKey(t *testing.T) {
	f := newFixture(t)
	canonical, err := json.Marshal(map[string]string{"crv": "Ed25519", "kty": "OKP", "x": f.key.jwk.X})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	sum := sha256.Sum256(canonical)
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); f.thumbprint != want {
		t.Errorf("thumbprint = %q, want %q, the RFC 7638 digest of %s", f.thumbprint, want, canonical)
	}

	published := f.key.jwk
	published.KeyID = "a name the directory gave itself"
	if _, err := NewKeyring().Add(testDirectory, published); !errors.Is(err, ErrThumbprintMismatch) {
		t.Errorf("error = %v, want %v: a kid is not taken on its word", err, ErrThumbprintMismatch)
	}
	published.KeyID = f.thumbprint
	if _, err := NewKeyring().Add(testDirectory, published); err != nil {
		t.Errorf("Add with the kid the key thumbprints to: %v", err)
	}
	if _, err := NewKeyring().Add("http://crawler.example/directory", f.key.jwk); !errors.Is(err, ErrNotHTTPS) {
		t.Errorf("error = %v, want %v", err, ErrNotHTTPS)
	}
	if _, ok := f.keys.Lookup(testDirectory, "another thumbprint"); ok {
		t.Error("Lookup found a key under a thumbprint nothing was recorded under")
	}
}

func TestJWKRefusals(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	valid := newKey(t).jwk

	// The last character of the key material holds four bits of key and two bits
	// of padding, so changing the padding decodes to the same key and encodes to
	// another string, which would thumbprint to another name for one key.
	idx := strings.IndexByte(alphabet, valid.X[len(valid.X)-1])
	noncanonical := valid.X[:len(valid.X)-1] + string(alphabet[(idx&^3)|((idx+1)&3)])

	cases := []struct {
		name string
		jwk  JWK
		want error
	}{
		{"a symmetric key", JWK{Kty: "oct", Crv: "Ed25519", X: valid.X}, ErrAlgorithm},
		{"another curve", JWK{Kty: "OKP", Crv: "X25519", X: valid.X}, ErrAlgorithm},
		{"an algorithm that is not EdDSA", JWK{Kty: "OKP", Crv: "Ed25519", X: valid.X, Alg: "HS256"}, ErrAlgorithm},
		{"key material that is not base64url", JWK{Kty: "OKP", Crv: "Ed25519", X: "not base64url"}, ErrKeyMaterial},
		{"key material of the wrong length", JWK{Kty: "OKP", Crv: "Ed25519", X: valid.X[:40]}, ErrKeyMaterial},
		{"key material that is not canonically encoded", JWK{Kty: "OKP", Crv: "Ed25519", X: noncanonical}, ErrKeyMaterial},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.jwk.PublicKey(); !errors.Is(err, c.want) {
				t.Errorf("PublicKey error = %v, want it to be %v", err, c.want)
			}
			if _, err := c.jwk.Thumbprint(); !errors.Is(err, c.want) {
				t.Errorf("Thumbprint error = %v, want it to be %v: a key that does not decode has no name", err, c.want)
			}
			if _, err := NewKeyring().Add(testDirectory, c.jwk); !errors.Is(err, c.want) {
				t.Errorf("Add error = %v, want it to be %v", err, c.want)
			}
		})
	}
}
