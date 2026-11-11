package webbotauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/polycratia/crawlwarrant/internal/sfv"
)

// Draft is the Web Bot Auth revision Verify follows, pinned here so a verdict
// says which document it was reached under.
const Draft = "draft-ietf-webbotauth-httpsig-protocol-00"

// Tag is the tag parameter a Web Bot Auth signature carries. A signature
// tagged anything else belongs to another protocol and is refused.
const Tag = "web-bot-auth"

// DefaultSkew is how far created and expires may fall outside the window when
// the keyring sets no Skew of its own.
const DefaultSkew = 5 * time.Second

// MaxLifetime is the longest signature lifetime the draft asks for. A longer
// one is reported in the verdict rather than refused.
const MaxLifetime = 24 * time.Hour

// Kinds of Reason.
const (
	// ReasonReplayable reports a signature nothing stops from being sent again
	// inside its window.
	ReasonReplayable = "replayable within window"
	// ReasonLongLifetime reports a lifetime above MaxLifetime.
	ReasonLongLifetime = "lifetime above 24 hours"
	// ReasonLegacyAgent reports a directory named by the legacy bare string form
	// of Signature-Agent.
	ReasonLegacyAgent = "legacy signature-agent"
)

// Reason is what a verdict records about the signature it verified. A reason
// is never a refusal: it is what an audit could not otherwise see.
type Reason struct {
	Kind    string
	Message string
}

var (
	// ErrNoSignature reports a request carrying no Web Bot Auth signature, or a
	// Signature field holding no bytes for the label being verified.
	ErrNoSignature = errors.New("the request carries no Web Bot Auth signature")
	// ErrTag reports a Signature-Input naming no signature tagged web-bot-auth.
	ErrTag = errors.New("a Web Bot Auth signature is tagged " + Tag)
	// ErrMissingParameter reports a signature that left out created, expires or keyid.
	ErrMissingParameter = errors.New("a Web Bot Auth signature gives created, expires and keyid")
	// ErrOutsideWindow reports a signature used outside the window created and
	// expires name, once the allowed skew is taken into account.
	ErrOutsideWindow = errors.New("the signature is used outside the window it names")
	// ErrCoveredComponents reports covered components that do not bind the
	// request to a host and to the field naming the key directory, or a covered
	// field the request does not carry.
	ErrCoveredComponents = errors.New("the covered components must bind the authority and the Signature-Agent field")
	// ErrUnsupportedComponent reports a covered component this package does not
	// rebuild, which leaves the signature base unverifiable rather than wrong.
	ErrUnsupportedComponent = errors.New("the signature covers a component this package does not rebuild")
	// ErrAlgorithm reports anything but Ed25519: HMAC and the other algorithms
	// are refused.
	ErrAlgorithm = errors.New("Web Bot Auth signs with Ed25519 only")
	// ErrKeyMaterial reports a JWK whose x member is not an Ed25519 public key.
	ErrKeyMaterial = errors.New("an Ed25519 JWK carries 32 bytes of unpadded base64url key material")
	// ErrThumbprintMismatch reports a keyid, or a published kid, that is not the
	// RFC 7638 thumbprint computed here from the key itself.
	ErrThumbprintMismatch = errors.New("a keyid is the RFC 7638 thumbprint of the key it names")
	// ErrUnknownKey reports a thumbprint no key of that directory has.
	ErrUnknownKey = errors.New("no key of that directory has that thumbprint")
	// ErrNoAgent reports a request whose Signature-Agent field names no member
	// for the label of the signature.
	ErrNoAgent = errors.New("a Signature-Agent member must name the key directory of the signature label")
	// ErrSignature reports a signature the key does not verify.
	ErrSignature = errors.New("the signature does not verify under the key it names")
	// ErrReplay reports a signature the configured ReplayCache already saw.
	ErrReplay = errors.New("the signature was already seen inside its window")
)

// JWK is an Ed25519 public key as a directory publishes it (RFC 8037).
type JWK struct {
	Kty   string `json:"kty"`
	Crv   string `json:"crv"`
	X     string `json:"x"`
	Alg   string `json:"alg,omitempty"`
	KeyID string `json:"kid,omitempty"`
	Use   string `json:"use,omitempty"`
}

// PublicKey decodes the key material, which is an Ed25519 public key or
// nothing this package can verify with.
func (j JWK) PublicKey() (ed25519.PublicKey, error) {
	if j.Kty != "OKP" || j.Crv != "Ed25519" {
		return nil, fmt.Errorf("webbotauth: a %q key on curve %q: %w", j.Kty, j.Crv, ErrAlgorithm)
	}
	if j.Alg != "" && j.Alg != "EdDSA" {
		return nil, fmt.Errorf("webbotauth: the key declares alg %q: %w", j.Alg, ErrAlgorithm)
	}
	x, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("webbotauth: x %q is not unpadded base64url (%v): %w", j.X, err, ErrKeyMaterial)
	}
	if len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("webbotauth: x holds %d bytes, want %d: %w", len(x), ed25519.PublicKeySize, ErrKeyMaterial)
	}
	if base64.RawURLEncoding.EncodeToString(x) != j.X {
		return nil, fmt.Errorf("webbotauth: x %q is not the canonical encoding of its bytes, which would thumbprint to another key: %w", j.X, ErrKeyMaterial)
	}
	return ed25519.PublicKey(x), nil
}

// Thumbprint computes the RFC 7638 thumbprint of the key: the SHA-256 of the
// required members, crv, kty and x, in lexicographic order with no whitespace,
// as unpadded base64url. It is computed from the key material, never read from
// the kid the directory published.
func (j JWK) Thumbprint() (string, error) {
	if _, err := j.PublicKey(); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(`{"crv":"` + j.Crv + `","kty":"` + j.Kty + `","x":"` + j.X + `"}`))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// ReplayCache records the signatures a verifier has already seen. It is
// opt-in: with no cache configured nothing checks a nonce, and the verdict
// says so.
type ReplayCache interface {
	// Seen records a key until its window closes at expires, and reports
	// whether that key was already recorded.
	Seen(key string, expires time.Time) bool
}

type keyIndex struct{ directory, thumbprint string }

// Keyring holds the Ed25519 keys directories published, looked up by the
// directory URL and the thumbprint together: a key proves nothing about a
// directory that did not publish it.
type Keyring struct {
	// Skew is how far created and expires may fall outside the window,
	// DefaultSkew when zero.
	Skew time.Duration
	// ReplayCache, when set, refuses a signature it has already seen.
	ReplayCache ReplayCache

	keys map[keyIndex]ed25519.PublicKey
}

// NewKeyring returns an empty keyring.
func NewKeyring() *Keyring {
	return &Keyring{keys: make(map[keyIndex]ed25519.PublicKey)}
}

// Add records one key a directory published, under the thumbprint computed
// here, and returns that thumbprint. A kid the directory published that is not
// the thumbprint of the key beside it is refused: the name of a key is derived
// from the key, not taken on its word.
func (k *Keyring) Add(directory string, j JWK) (string, error) {
	if err := checkHTTPS(directory); err != nil {
		return "", fmt.Errorf("webbotauth: key directory %q: %w", directory, err)
	}
	thumbprint, err := j.Thumbprint()
	if err != nil {
		return "", err
	}
	if j.KeyID != "" && j.KeyID != thumbprint {
		return "", fmt.Errorf("webbotauth: %s published kid %q for a key whose thumbprint is %q: %w", directory, j.KeyID, thumbprint, ErrThumbprintMismatch)
	}
	pub, err := j.PublicKey()
	if err != nil {
		return "", err
	}
	if k.keys == nil {
		k.keys = make(map[keyIndex]ed25519.PublicKey)
	}
	k.keys[keyIndex{directory, thumbprint}] = pub
	return thumbprint, nil
}

// Lookup returns the key a directory published under a thumbprint.
func (k *Keyring) Lookup(directory, thumbprint string) (ed25519.PublicKey, bool) {
	pub, ok := k.keys[keyIndex{directory, thumbprint}]
	return pub, ok
}

func (k *Keyring) skew() time.Duration {
	if k.Skew > 0 {
		return k.Skew
	}
	return DefaultSkew
}

// Verdict is a verified Web Bot Auth signature: which key of which directory
// signed what, and what the signature leaves open.
type Verdict struct {
	Label      string    // Signature-Input label that was verified
	Directory  string    // Signature-Agent URL the key was published at
	Thumbprint string    // RFC 7638 thumbprint, computed here and equal to the keyid
	Created    time.Time
	Expires    time.Time
	Nonce      string   // empty when the signature carried none
	Components []string // covered components, in the order the field gave them
	Base       string   // signature base that verified, rebuilt per RFC 9421
	Reasons    []Reason
}

// Verify checks the Web Bot Auth signature a request carries against the keys
// a directory published, as of now, following Draft. It returns the verdict of
// the signature it verified, or the refusal that stopped it.
func Verify(req *http.Request, keys *Keyring, now time.Time) (Verdict, error) {
	if keys == nil {
		return Verdict{}, errors.New("webbotauth: Verify needs a keyring: there is nothing to verify against")
	}
	input := req.Header.Get("Signature-Input")
	if input == "" {
		return Verdict{}, fmt.Errorf("webbotauth: no Signature-Input field: %w", ErrNoSignature)
	}
	sigs, err := ParseSignatureInput(input)
	if err != nil {
		return Verdict{}, err
	}
	sig, err := webBotAuth(sigs)
	if err != nil {
		return Verdict{}, err
	}
	params, err := rawParams(input, sig.Label)
	if err != nil {
		return Verdict{}, err
	}
	signature, err := signatureBytes(req.Header.Get("Signature"), sig.Label)
	if err != nil {
		return Verdict{}, err
	}
	directory, legacy, err := keyDirectory(req.Header.Get("Signature-Agent"), sig.Label)
	if err != nil {
		return Verdict{}, err
	}
	if err := checkComponents(sig); err != nil {
		return Verdict{}, err
	}
	if err := checkWindow(sig, now, keys.skew()); err != nil {
		return Verdict{}, err
	}
	if err := checkAlgorithm(sig, params); err != nil {
		return Verdict{}, err
	}
	if err := checkThumbprint(sig.KeyID); err != nil {
		return Verdict{}, err
	}
	pub, ok := keys.Lookup(directory, sig.KeyID)
	if !ok {
		return Verdict{}, fmt.Errorf("webbotauth: %s publishes no key with thumbprint %q: %w", directory, sig.KeyID, ErrUnknownKey)
	}
	base, err := signatureBase(req, sig, params)
	if err != nil {
		return Verdict{}, err
	}
	if !ed25519.Verify(pub, []byte(base), signature) {
		return Verdict{}, fmt.Errorf("webbotauth: signature %q of %s over %d bytes of signature base: %w", sig.Label, directory, len(base), ErrSignature)
	}

	v := Verdict{
		Label:      sig.Label,
		Directory:  directory,
		Thumbprint: sig.KeyID,
		Created:    sig.Created,
		Expires:    sig.Expires,
		Nonce:      sig.Nonce,
		Base:       base,
	}
	for _, c := range sig.Components {
		v.Components = append(v.Components, c.Name)
	}
	if legacy {
		v.Reasons = append(v.Reasons, Reason{ReasonLegacyAgent, fmt.Sprintf("%s was named by the bare string form of Signature-Agent, which is read on input and never produced", directory)})
	}
	if lifetime := sig.Expires.Sub(sig.Created); lifetime > MaxLifetime {
		v.Reasons = append(v.Reasons, Reason{ReasonLongLifetime, fmt.Sprintf("the signature lives %d hours, past the %d %s asks for: reported, not refused", int(lifetime/time.Hour), int(MaxLifetime/time.Hour), Draft)})
	}
	if keys.ReplayCache == nil {
		carried := "carries no nonce"
		if sig.Nonce != "" {
			carried = "carries a nonce nothing checks"
		}
		v.Reasons = append(v.Reasons, Reason{ReasonReplayable, fmt.Sprintf("the signature %s and no ReplayCache is configured: it can be sent again until %s", carried, sig.Expires.Format(time.RFC3339))})
		return v, nil
	}
	replayKey := sig.Nonce
	if replayKey == "" {
		replayKey = base64.StdEncoding.EncodeToString(signature)
	}
	if keys.ReplayCache.Seen(replayKey, sig.Expires) {
		return Verdict{}, fmt.Errorf("webbotauth: signature %q of %s was already seen inside the window ending %s: %w", sig.Label, directory, sig.Expires.Format(time.RFC3339), ErrReplay)
	}
	return v, nil
}

func webBotAuth(sigs []Signature) (Signature, error) {
	seen := make([]string, 0, len(sigs))
	for _, s := range sigs {
		if s.Tag == Tag {
			return s, nil
		}
		seen = append(seen, fmt.Sprintf("%s tagged %q", s.Label, s.Tag))
	}
	return Signature{}, fmt.Errorf("webbotauth: Signature-Input names %s: %w", strings.Join(seen, ", "), ErrTag)
}

// rawParams returns the signature parameters as the field spelled them, which
// the @signature-params line of the signature base is rebuilt from.
func rawParams(field, label string) (sfv.Params, error) {
	d, err := sfv.ParseDictionary(field)
	if err != nil {
		return nil, fmt.Errorf("webbotauth: Signature-Input: %w", err)
	}
	v, ok := d.Get(label)
	if !ok {
		return nil, fmt.Errorf("webbotauth: Signature-Input names no label %q: %w", label, ErrNoSignature)
	}
	return v.Params, nil
}

func signatureBytes(field, label string) ([]byte, error) {
	if field == "" {
		return nil, fmt.Errorf("webbotauth: no Signature field: %w", ErrNoSignature)
	}
	d, err := sfv.ParseDictionary(field)
	if err != nil {
		return nil, fmt.Errorf("webbotauth: Signature: %w", err)
	}
	v, ok := d.Get(label)
	if !ok {
		return nil, fmt.Errorf("webbotauth: Signature holds nothing for label %q: %w", label, ErrNoSignature)
	}
	if v.Kind != sfv.KindByteSequence {
		return nil, fmt.Errorf("webbotauth: Signature %q is a %v, want the byte sequence of the signature: %w", label, v.Kind, ErrNoSignature)
	}
	if len(v.Bytes) != ed25519.SignatureSize {
		return nil, fmt.Errorf("webbotauth: Signature %q holds %d bytes, want the %d of an Ed25519 signature: %w", label, len(v.Bytes), ed25519.SignatureSize, ErrAlgorithm)
	}
	return v.Bytes, nil
}

func keyDirectory(field, label string) (directory string, legacy bool, err error) {
	if field == "" {
		return "", false, fmt.Errorf("webbotauth: no Signature-Agent field: %w", ErrNoAgent)
	}
	sa, err := ParseSignatureAgent(field)
	if err != nil {
		return "", false, err
	}
	if sa.Legacy {
		return sa.Agents[0].URL, true, nil
	}
	for _, a := range sa.Agents {
		if a.Label == label {
			return a.URL, false, nil
		}
	}
	return "", false, fmt.Errorf("webbotauth: Signature-Agent names no member %q, the label of the signature: %w", label, ErrNoAgent)
}

func checkComponents(sig Signature) error {
	var bound, agent bool
	for _, c := range sig.Components {
		switch strings.ToLower(c.Name) {
		case "@authority", "@target-uri":
			bound = true
		case "signature-agent":
			agent = true
		}
	}
	if !bound {
		return fmt.Errorf("webbotauth: signature %q covers neither @authority nor @target-uri, so it is not bound to the host it was sent to: %w", sig.Label, ErrCoveredComponents)
	}
	if !agent {
		return fmt.Errorf("webbotauth: signature %q does not cover signature-agent, the field naming its key directory: %w", sig.Label, ErrCoveredComponents)
	}
	return nil
}

func checkWindow(sig Signature, now time.Time, skew time.Duration) error {
	if sig.Created.IsZero() {
		return fmt.Errorf("webbotauth: signature %q gives no created: %w", sig.Label, ErrMissingParameter)
	}
	if sig.Expires.IsZero() {
		return fmt.Errorf("webbotauth: signature %q gives no expires: %w", sig.Label, ErrMissingParameter)
	}
	if sig.Expires.Before(sig.Created) {
		return fmt.Errorf("webbotauth: signature %q expires at %s, before it was created at %s: %w", sig.Label, sig.Expires.Format(time.RFC3339), sig.Created.Format(time.RFC3339), ErrOutsideWindow)
	}
	if sig.Created.After(now.Add(skew)) {
		return fmt.Errorf("webbotauth: signature %q was created at %s, past %s and the %s of skew allowed: %w", sig.Label, sig.Created.Format(time.RFC3339), now.Format(time.RFC3339), skew, ErrOutsideWindow)
	}
	if now.After(sig.Expires.Add(skew)) {
		return fmt.Errorf("webbotauth: signature %q expired at %s, before %s less the %s of skew allowed: %w", sig.Label, sig.Expires.Format(time.RFC3339), now.Format(time.RFC3339), skew, ErrOutsideWindow)
	}
	return nil
}

func checkAlgorithm(sig Signature, params sfv.Params) error {
	v, ok := params.Get("alg")
	if !ok {
		return nil
	}
	if v.Kind != sfv.KindString {
		return fmt.Errorf("webbotauth: the alg parameter of %q is a %v, want the string ed25519: %w", sig.Label, v.Kind, ErrAlgorithm)
	}
	if v.Str != "ed25519" {
		return fmt.Errorf("webbotauth: signature %q names alg %q: %w", sig.Label, v.Str, ErrAlgorithm)
	}
	return nil
}

func checkThumbprint(keyid string) error {
	if keyid == "" {
		return fmt.Errorf("webbotauth: the signature gives no keyid: %w", ErrMissingParameter)
	}
	raw, err := base64.RawURLEncoding.DecodeString(keyid)
	if err != nil || len(raw) != sha256.Size {
		return fmt.Errorf("webbotauth: keyid %q is not the unpadded base64url of a SHA-256 digest: %w", keyid, ErrThumbprintMismatch)
	}
	return nil
}

// signatureBase rebuilds the signature base per RFC 9421, Section 2.5: one
// line per covered component, then the @signature-params line holding the
// inner list and the parameters as the field spelled them.
func signatureBase(req *http.Request, sig Signature, params sfv.Params) (string, error) {
	var b strings.Builder
	for _, c := range sig.Components {
		value, err := componentValue(req, c)
		if err != nil {
			return "", err
		}
		b.WriteString(serializeString(c.Name))
		b.WriteString(serializeParams(c.Params))
		b.WriteString(": ")
		b.WriteString(value)
		b.WriteString("\n")
	}
	b.WriteString(`"@signature-params": (`)
	for i, c := range sig.Components {
		if i > 0 {
			b.WriteString(" ")
		}
		b.WriteString(serializeString(c.Name))
		b.WriteString(serializeParams(c.Params))
	}
	b.WriteString(")")
	b.WriteString(serializeParams(params))
	return b.String(), nil
}

func componentValue(req *http.Request, c Component) (string, error) {
	for _, p := range c.Params {
		return "", fmt.Errorf("webbotauth: covered component %q carries the %q parameter: %w", c.Name, p.Key, ErrUnsupportedComponent)
	}
	name := strings.ToLower(c.Name)
	if strings.HasPrefix(name, "@") {
		return derivedComponent(req, name)
	}
	if name == "host" {
		if req.Host == "" {
			return "", fmt.Errorf("webbotauth: the request carries no host: %w", ErrCoveredComponents)
		}
		return req.Host, nil
	}
	values := req.Header.Values(name)
	if len(values) == 0 {
		return "", fmt.Errorf("webbotauth: the signature covers the %s field, which the request does not carry: %w", name, ErrCoveredComponents)
	}
	fields := make([]string, len(values))
	for i, v := range values {
		fields[i] = strings.TrimSpace(v)
	}
	return strings.Join(fields, ", "), nil
}

func derivedComponent(req *http.Request, name string) (string, error) {
	switch name {
	case "@method":
		return strings.ToUpper(req.Method), nil
	case "@authority":
		return authority(req), nil
	case "@scheme":
		return scheme(req), nil
	case "@path":
		return path(req), nil
	case "@query":
		return "?" + req.URL.RawQuery, nil
	case "@target-uri":
		target := scheme(req) + "://" + authority(req) + path(req)
		if req.URL.RawQuery != "" {
			target += "?" + req.URL.RawQuery
		}
		return target, nil
	}
	return "", fmt.Errorf("webbotauth: covered component %q: %w", name, ErrUnsupportedComponent)
}

func authority(req *http.Request) string {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	host = strings.ToLower(host)
	switch scheme(req) {
	case "https":
		return strings.TrimSuffix(host, ":443")
	case "http":
		return strings.TrimSuffix(host, ":80")
	}
	return host
}

func scheme(req *http.Request) string {
	if req.URL.Scheme != "" {
		return strings.ToLower(req.URL.Scheme)
	}
	if req.TLS != nil {
		return "https"
	}
	return "http"
}

func path(req *http.Request) string {
	if p := req.URL.EscapedPath(); p != "" {
		return p
	}
	return "/"
}

func serializeParams(params sfv.Params) string {
	var b strings.Builder
	for _, p := range params {
		b.WriteString(";")
		b.WriteString(p.Key)
		if p.Value.Kind == sfv.KindBoolean && p.Value.Bool {
			continue
		}
		b.WriteString("=")
		b.WriteString(serializeValue(p.Value))
	}
	return b.String()
}

func serializeValue(v sfv.Value) string {
	switch v.Kind {
	case sfv.KindString:
		return serializeString(v.Str)
	case sfv.KindToken:
		return v.Str
	case sfv.KindInteger:
		return strconv.FormatInt(v.Int, 10)
	case sfv.KindByteSequence:
		return ":" + base64.StdEncoding.EncodeToString(v.Bytes) + ":"
	case sfv.KindBoolean:
		if v.Bool {
			return "?1"
		}
		return "?0"
	case sfv.KindInnerList:
		var b strings.Builder
		b.WriteString("(")
		for i, item := range v.Items {
			if i > 0 {
				b.WriteString(" ")
			}
			b.WriteString(serializeValue(item))
			b.WriteString(serializeParams(item.Params))
		}
		b.WriteString(")")
		return b.String()
	}
	return ""
}

func serializeString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	b.WriteByte('"')
	return b.String()
}
