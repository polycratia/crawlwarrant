package sfv

import (
	"errors"
	"reflect"
	"testing"
)

func get(t *testing.T, d Dictionary, key string) Value {
	t.Helper()
	v, ok := d.Get(key)
	if !ok {
		t.Fatalf("the dictionary names no %q: %+v", key, d)
	}
	return v
}

func TestParseDictionaryValues(t *testing.T) {
	const field = `a="x", b=12, c=tok:en, d=:aGk=:, e, f=?0, g=("one" "two";p=1);q="r", h=-3, a="again"`
	d, err := ParseDictionary(field)
	if err != nil {
		t.Fatalf("ParseDictionary: %v", err)
	}

	keys := make([]string, 0, len(d))
	for _, m := range d {
		keys = append(keys, m.Key)
	}
	if want := []string{"a", "b", "c", "d", "e", "f", "g", "h"}; !reflect.DeepEqual(keys, want) {
		t.Errorf("keys = %v, want %v: a key given twice keeps its first position", keys, want)
	}

	if v := get(t, d, "a"); v.Kind != KindString || v.Str != "again" {
		t.Errorf("a = %+v, want the last string the field gave for the key", v)
	}
	if v := get(t, d, "b"); v.Kind != KindInteger || v.Int != 12 {
		t.Errorf("b = %+v, want the integer 12", v)
	}
	if v := get(t, d, "c"); v.Kind != KindToken || v.Str != "tok:en" {
		t.Errorf("c = %+v, want the token tok:en", v)
	}
	if v := get(t, d, "d"); v.Kind != KindByteSequence || string(v.Bytes) != "hi" {
		t.Errorf("d = %+v, want the decoded byte sequence hi", v)
	}
	if v := get(t, d, "e"); v.Kind != KindBoolean || !v.Bool {
		t.Errorf("e = %+v, want the implied true of a bare key", v)
	}
	if v := get(t, d, "f"); v.Kind != KindBoolean || v.Bool {
		t.Errorf("f = %+v, want false", v)
	}
	if v := get(t, d, "h"); v.Kind != KindInteger || v.Int != -3 {
		t.Errorf("h = %+v, want the integer -3", v)
	}

	g := get(t, d, "g")
	if g.Kind != KindInnerList || len(g.Items) != 2 {
		t.Fatalf("g = %+v, want an inner list of two members", g)
	}
	if g.Items[0].Kind != KindString || g.Items[0].Str != "one" {
		t.Errorf("first member = %+v, want the string one", g.Items[0])
	}
	if p, ok := g.Items[1].Params.Get("p"); !ok || p.Kind != KindInteger || p.Int != 1 {
		t.Errorf("second member parameters = %+v, want p=1 on the member", g.Items[1].Params)
	}
	if q, ok := g.Params.Get("q"); !ok || q.Kind != KindString || q.Str != "r" {
		t.Errorf("inner list parameters = %+v, want q=\"r\" on the list", g.Params)
	}
}

func TestParseDictionaryStringEscapes(t *testing.T) {
	d, err := ParseDictionary(`a="say \"hi\"\\"`)
	if err != nil {
		t.Fatalf("ParseDictionary: %v", err)
	}
	v := get(t, d, "a")
	if want := `say "hi"\`; v.Kind != KindString || v.Str != want {
		t.Errorf("a = %+v, want the string %q", v, want)
	}
}

func TestParseDictionaryEmptyFieldIsNoError(t *testing.T) {
	for _, field := range []string{"", " ", "\t "} {
		d, err := ParseDictionary(field)
		if err != nil {
			t.Errorf("ParseDictionary(%q): %v, want the empty dictionary: a field that declares nothing is not malformed", field, err)
		}
		if len(d) != 0 {
			t.Errorf("ParseDictionary(%q) = %+v, want no members", field, d)
		}
	}
}

func TestParseDictionaryRefusals(t *testing.T) {
	cases := []struct {
		name   string
		field  string
		offset int
	}{
		{"an uppercase key", `A="x"`, 0},
		{"a member with no key", `="x"`, 0},
		{"a missing comma", `a="x" b="y"`, 6},
		{"a trailing comma", `a="x", `, 6},
		{"a value missing after =", `a=`, 1},
		{"an unterminated string", `a="x`, 2},
		{"a control byte in a string", "a=\"x\ty\"", 4},
		{"an unknown string escape", `a="x\ny"`, 5},
		{"an unterminated inner list", `a=("x"`, 2},
		{"two inner list members with no space", `a=("x""y")`, 6},
		{"an unterminated byte sequence", `a=:aGk=`, 2},
		{"a byte sequence that is not base64", `a=:a*b:`, 3},
		{"a decimal", `a=1.5`, 3},
		{"an integer past 15 digits", `a=1234567890123456`, 2},
		{"a date", `a=@1735689600`, 2},
		{"a display string", `a=%"x"`, 2},
		{"a bare question mark", `a=?`, 2},
		{"a boolean that is neither ?0 nor ?1", `a=?2`, 3},
		{"a byte that begins no value", `a=<x>`, 2},
		{"a parameter with no key", `a="x";=1`, 6},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseDictionary(c.field)
			var se *SyntaxError
			if !errors.As(err, &se) {
				t.Fatalf("ParseDictionary(%q) error = %v, want a *SyntaxError naming the offset", c.field, err)
			}
			if se.Offset != c.offset {
				t.Errorf("ParseDictionary(%q) refused at offset %d, want %d (%v)", c.field, se.Offset, c.offset, se)
			}
			if se.Offset >= len(c.field) {
				t.Errorf("offset %d is past the %d bytes of input", se.Offset, len(c.field))
			}
			if se.Msg == "" {
				t.Error("the error carries no message")
			}
		})
	}
}

func TestParseItem(t *testing.T) {
	v, err := ParseItem(` "https://chatgpt.com";type=directory`)
	if err != nil {
		t.Fatalf("ParseItem: %v", err)
	}
	if v.Kind != KindString || v.Str != "https://chatgpt.com" {
		t.Errorf("item = %+v, want the bare string", v)
	}
	if p, ok := v.Params.Get("type"); !ok || p.Kind != KindToken || p.Str != "directory" {
		t.Errorf("parameters = %+v, want type=directory", v.Params)
	}

	var se *SyntaxError
	if _, err := ParseItem(`"x" y`); !errors.As(err, &se) || se.Offset != 4 {
		t.Errorf("ParseItem with trailing input: error = %v, want a refusal at offset 4", err)
	}
}
