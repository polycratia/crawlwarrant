package sfv

import (
	"errors"
	"testing"
)

// FuzzDictionary asserts the two things a caller relies on for any input at
// all: parsing never panics, and a refusal names an offset inside the input it
// refused, so the caller can quote the field around it.
func FuzzDictionary(f *testing.F) {
	seeds := []string{
		"",
		" ",
		`a="x"`,
		`a=:aGk=:, b=?1, c=tok, d`,
		`sig1=("@authority" "signature-agent");created=1735689600;keyid="k";tag="web-bot-auth"`,
		`sig1="https://chatgpt.com/.well-known/http-message-signatures-directory";type=jwks_uri`,
		`a=(`,
		`a=1.5`,
		`A="x"`,
		`a="x", `,
		"a=\"\x00\"",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, field string) {
		_, err := ParseDictionary(field)
		if err == nil {
			return
		}
		var se *SyntaxError
		if !errors.As(err, &se) {
			t.Fatalf("ParseDictionary(%q) error = %v, want a *SyntaxError", field, err)
		}
		if se.Offset < 0 || se.Offset >= len(field) {
			t.Fatalf("ParseDictionary(%q) refused at offset %d, outside the %d bytes of input", field, se.Offset, len(field))
		}
	})
}
