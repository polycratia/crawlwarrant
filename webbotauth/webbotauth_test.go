package webbotauth

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/polycratia/crawlwarrant/internal/sfv"
)

func TestParseSignatureAgentDictionary(t *testing.T) {
	const field = `sig1="https://chatgpt.com/.well-known/http-message-signatures-directory", keys="https://example.com/jwks.json";type=jwks_uri, meta="https://example.com/cimd";type="cimd", odd="https://example.com/x";type=registry`
	got, err := ParseSignatureAgent(field)
	if err != nil {
		t.Fatalf("ParseSignatureAgent: %v", err)
	}
	if got.Legacy {
		t.Error("Legacy = true, want false: the dictionary form is the current one")
	}
	want := []Agent{
		{Label: "sig1", URL: "https://chatgpt.com/.well-known/http-message-signatures-directory", Type: TypeDirectory},
		{Label: "keys", URL: "https://example.com/jwks.json", Type: TypeJWKS, RawType: "jwks_uri"},
		{Label: "meta", URL: "https://example.com/cimd", Type: TypeCIMD, RawType: "cimd"},
		{Label: "odd", URL: "https://example.com/x", Type: TypeOther, RawType: "registry"},
	}
	if !reflect.DeepEqual(got.Agents, want) {
		t.Errorf("agents = %+v, want %+v: a type this package does not know is kept, not refused", got.Agents, want)
	}
}

func TestParseSignatureAgentLegacyBareString(t *testing.T) {
	got, err := ParseSignatureAgent(`"https://chatgpt.com"`)
	if err != nil {
		t.Fatalf("ParseSignatureAgent: %v", err)
	}
	if !got.Legacy {
		t.Error("Legacy = false, want true: the bare string is the legacy form ChatGPT agent sends")
	}
	want := []Agent{{URL: "https://chatgpt.com", Type: TypeDirectory}}
	if !reflect.DeepEqual(got.Agents, want) {
		t.Errorf("agents = %+v, want %+v", got.Agents, want)
	}
}

func TestParseSignatureAgentRefusals(t *testing.T) {
	cases := []struct {
		name  string
		field string
		want  error
	}{
		{"an http member", `sig1="http://example.com/directory"`, ErrNotHTTPS},
		{"a legacy http string", `"http://chatgpt.com"`, ErrNotHTTPS},
		{"a host with no scheme", `sig1="example.com/directory"`, ErrNotHTTPS},
		{"a token instead of a string", `sig1=https://example.com`, ErrNotAString},
		{"an inner list", `sig1=("https://example.com")`, ErrNotAString},
		{"an integer", `sig1=1`, ErrNotAString},
		{"an empty field", ``, nil},
		{"a malformed dictionary", `sig1="https://example.com" sig2="https://example.org"`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseSignatureAgent(c.field)
			if err == nil {
				t.Fatalf("ParseSignatureAgent(%q) = no error, want a refusal", c.field)
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Errorf("error = %v, want it to be %v", err, c.want)
			}
		})
	}
}

func TestParseSignatureAgentNamesTheOffset(t *testing.T) {
	_, err := ParseSignatureAgent(`sig1="https://example.com`)
	var se *sfv.SyntaxError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want an *sfv.SyntaxError", err)
	}
	if se.Offset != 5 {
		t.Errorf("offset = %d, want 5, where the unterminated string opens", se.Offset)
	}
}

func TestParseSignatureInput(t *testing.T) {
	const field = `sig1=("@authority" "signature-agent" "content-digest";sf);created=1735689600;expires=1735689900;keyid="poqkLGiymh_W0uP6PZFw";tag="web-bot-auth";nonce="e8N7S2MFd/qrd6T2R3tdfA", sig2=("@method");keyid="other"`
	sigs, err := ParseSignatureInput(field)
	if err != nil {
		t.Fatalf("ParseSignatureInput: %v", err)
	}
	if len(sigs) != 2 {
		t.Fatalf("signatures = %+v, want both labels", sigs)
	}

	s := sigs[0]
	if s.Label != "sig1" {
		t.Errorf("label = %q, want sig1", s.Label)
	}
	wantNames := []string{"@authority", "signature-agent", "content-digest"}
	if len(s.Components) != len(wantNames) {
		t.Fatalf("components = %+v, want %v", s.Components, wantNames)
	}
	for i, name := range wantNames {
		if s.Components[i].Name != name {
			t.Errorf("component %d = %q, want %q", i, s.Components[i].Name, name)
		}
	}
	if v, ok := s.Components[2].Params.Get("sf"); !ok || v.Kind != sfv.KindBoolean || !v.Bool {
		t.Errorf("content-digest parameters = %+v, want sf set on the component", s.Components[2].Params)
	}
	if want := time.Unix(1735689600, 0).UTC(); !s.Created.Equal(want) {
		t.Errorf("created = %v, want %v", s.Created, want)
	}
	if want := time.Unix(1735689900, 0).UTC(); !s.Expires.Equal(want) {
		t.Errorf("expires = %v, want %v", s.Expires, want)
	}
	if s.KeyID != "poqkLGiymh_W0uP6PZFw" || s.Tag != "web-bot-auth" || s.Nonce != "e8N7S2MFd/qrd6T2R3tdfA" {
		t.Errorf("keyid = %q, tag = %q, nonce = %q, want all three as the field gave them", s.KeyID, s.Tag, s.Nonce)
	}

	if !sigs[1].Created.IsZero() {
		t.Errorf("created of sig2 = %v, want the zero time: the field gave no created parameter", sigs[1].Created)
	}
	if sigs[1].KeyID != "other" {
		t.Errorf("keyid of sig2 = %q, want other", sigs[1].KeyID)
	}
}

func TestParseSignatureInputRefusals(t *testing.T) {
	cases := []struct {
		name  string
		field string
	}{
		{"a value that is not an inner list", `sig1="@authority"`},
		{"a component that is not a string", `sig1=(authority)`},
		{"created that is not an integer", `sig1=("@authority");created="1735689600"`},
		{"expires that is not an integer", `sig1=("@authority");expires=now`},
		{"keyid that is not a string", `sig1=("@authority");keyid=abc`},
		{"nonce that is not a string", `sig1=("@authority");nonce=:aGk=:`},
		{"an empty field", ``},
		{"a malformed dictionary", `sig1=("@authority"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseSignatureInput(c.field); err == nil {
				t.Fatalf("ParseSignatureInput(%q) = no error, want a refusal", c.field)
			}
		})
	}
}
