// Package webbotauth reads the header fields a Web Bot Auth request carries:
// Signature-Agent, which names where the keys that signed the request are
// published, and Signature-Input, which says what each signature covers. Both
// are RFC 9651 structured fields, and a field that does not parse is refused
// with the byte offset it was refused at.
package webbotauth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/polycratia/crawlwarrant/internal/sfv"
)

// AgentType is what a Signature-Agent member says its URL serves.
type AgentType uint8

const (
	// TypeDirectory is an HTTP message signatures directory, the type a member
	// that gives no type parameter has.
	TypeDirectory AgentType = iota + 1
	// TypeJWKS is a JWK Set.
	TypeJWKS
	// TypeCIMD is a cryptographic identity metadata document.
	TypeCIMD
	// TypeOther is a type this package does not recognise. The member is kept
	// and the type ignored: a document we cannot read is not a malformed field.
	TypeOther
)

func (t AgentType) String() string {
	switch t {
	case TypeDirectory:
		return "directory"
	case TypeJWKS:
		return "jwks_uri"
	case TypeCIMD:
		return "cimd"
	case TypeOther:
		return "other"
	}
	return "unset"
}

// Agent is one member of a Signature-Agent field.
type Agent struct {
	Label   string // dictionary key, empty for the legacy bare string
	URL     string // https URL the member carries
	Type    AgentType
	RawType string // type parameter as the field spelled it, empty when it gave none
}

// SignatureAgent is a parsed Signature-Agent field.
type SignatureAgent struct {
	Agents []Agent
	// Legacy reports the bare string form, which ChatGPT agent sends as
	// `Signature-Agent: "https://chatgpt.com"`. It is read on input and never
	// produced.
	Legacy bool
}

// ErrNotHTTPS reports a Signature-Agent member whose URL is not https: keys
// fetched over a plain connection prove nothing.
var ErrNotHTTPS = errors.New("a Signature-Agent URL must be an https URL")

// ErrNotAString reports a Signature-Agent member that is not a string.
var ErrNotAString = errors.New("a Signature-Agent member is a string holding an https URL")

// ParseSignatureAgent reads a Signature-Agent field as a dictionary of https
// URLs, each with an optional type parameter. The legacy bare string form is
// accepted too, and reported as Legacy.
func ParseSignatureAgent(field string) (SignatureAgent, error) {
	if strings.TrimLeft(field, " \t") == "" {
		return SignatureAgent{}, errors.New("webbotauth: Signature-Agent is empty: it names no key directory")
	}
	if strings.TrimLeft(field, " \t")[0] == '"' {
		v, err := sfv.ParseItem(field)
		if err != nil {
			return SignatureAgent{}, fmt.Errorf("webbotauth: Signature-Agent: %w", err)
		}
		a, err := agent("", v)
		if err != nil {
			return SignatureAgent{}, err
		}
		return SignatureAgent{Agents: []Agent{a}, Legacy: true}, nil
	}
	d, err := sfv.ParseDictionary(field)
	if err != nil {
		return SignatureAgent{}, fmt.Errorf("webbotauth: Signature-Agent: %w", err)
	}
	agents := make([]Agent, 0, len(d))
	for _, m := range d {
		a, err := agent(m.Key, m.Value)
		if err != nil {
			return SignatureAgent{}, err
		}
		agents = append(agents, a)
	}
	return SignatureAgent{Agents: agents}, nil
}

func agent(label string, v sfv.Value) (Agent, error) {
	where := "the Signature-Agent value"
	if label != "" {
		where = fmt.Sprintf("Signature-Agent member %q", label)
	}
	if v.Kind != sfv.KindString {
		return Agent{}, fmt.Errorf("webbotauth: %s is a %v: %w", where, v.Kind, ErrNotAString)
	}
	if err := checkHTTPS(v.Str); err != nil {
		return Agent{}, fmt.Errorf("webbotauth: %s: %w", where, err)
	}
	a := Agent{Label: label, URL: v.Str, Type: TypeDirectory}
	if t, ok := v.Params.Get("type"); ok {
		if t.Kind == sfv.KindToken || t.Kind == sfv.KindString {
			a.RawType = t.Str
		}
		a.Type = agentType(a.RawType)
	}
	return a, nil
}

func agentType(raw string) AgentType {
	switch raw {
	case "directory":
		return TypeDirectory
	case "jwks_uri":
		return TypeJWKS
	case "cimd":
		return TypeCIMD
	}
	return TypeOther
}

func checkHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q is not a URL (%v): %w", raw, err, ErrNotHTTPS)
	}
	if !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
		return fmt.Errorf("%q is not https: %w", raw, ErrNotHTTPS)
	}
	return nil
}

// Component is one covered component of a signature base, with the parameters
// the inner list member carried, such as req or sf.
type Component struct {
	Name   string
	Params sfv.Params
}

// Signature is one label of a Signature-Input field: what the signature covers
// and the parameters that describe it.
type Signature struct {
	Label      string
	Components []Component
	Created    time.Time // zero when the field gave no created parameter
	Expires    time.Time // zero when the field gave no expires parameter
	KeyID      string
	Tag        string
	Nonce      string
}

// ParseSignatureInput reads a Signature-Input field: per label, the covered
// components and the created, expires, keyid, tag and nonce parameters.
func ParseSignatureInput(field string) ([]Signature, error) {
	d, err := sfv.ParseDictionary(field)
	if err != nil {
		return nil, fmt.Errorf("webbotauth: Signature-Input: %w", err)
	}
	if len(d) == 0 {
		return nil, errors.New("webbotauth: Signature-Input is empty: it names no signature")
	}
	sigs := make([]Signature, 0, len(d))
	for _, m := range d {
		if m.Value.Kind != sfv.KindInnerList {
			return nil, fmt.Errorf("webbotauth: Signature-Input %q is a %v, want the inner list of covered components", m.Key, m.Value.Kind)
		}
		s := Signature{Label: m.Key}
		for _, item := range m.Value.Items {
			if item.Kind != sfv.KindString {
				return nil, fmt.Errorf("webbotauth: Signature-Input %q: a covered component is a %v, want a string", m.Key, item.Kind)
			}
			s.Components = append(s.Components, Component{Name: item.Str, Params: item.Params})
		}
		if err := s.readParams(m.Value.Params); err != nil {
			return nil, fmt.Errorf("webbotauth: Signature-Input %q: %w", m.Key, err)
		}
		sigs = append(sigs, s)
	}
	return sigs, nil
}

func (s *Signature) readParams(params sfv.Params) error {
	for _, p := range []struct {
		name string
		dst  *time.Time
	}{{"created", &s.Created}, {"expires", &s.Expires}} {
		v, ok := params.Get(p.name)
		if !ok {
			continue
		}
		if v.Kind != sfv.KindInteger {
			return fmt.Errorf("the %s parameter is a %v, want an integer unix timestamp", p.name, v.Kind)
		}
		*p.dst = time.Unix(v.Int, 0).UTC()
	}
	for _, p := range []struct {
		name string
		dst  *string
	}{{"keyid", &s.KeyID}, {"tag", &s.Tag}, {"nonce", &s.Nonce}} {
		v, ok := params.Get(p.name)
		if !ok {
			continue
		}
		if v.Kind != sfv.KindString {
			return fmt.Errorf("the %s parameter is a %v, want a string", p.name, v.Kind)
		}
		*p.dst = v.Str
	}
	return nil
}
