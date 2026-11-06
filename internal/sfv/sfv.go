// Package sfv parses the subset of RFC 9651 structured field values Web Bot
// Auth needs: dictionaries, inner lists, strings, tokens, integers, byte
// sequences, booleans and the parameters of each. A form the subset leaves out,
// a decimal or a date among them, is refused like any other malformed input:
// with the byte offset it was refused at, so a caller can quote the field
// around it.
package sfv

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// Kind is what a parsed value is.
type Kind uint8

const (
	KindInvalid Kind = iota
	KindString
	KindToken
	KindInteger
	KindByteSequence
	KindBoolean
	KindInnerList
)

func (k Kind) String() string {
	switch k {
	case KindString:
		return "string"
	case KindToken:
		return "token"
	case KindInteger:
		return "integer"
	case KindByteSequence:
		return "byte sequence"
	case KindBoolean:
		return "boolean"
	case KindInnerList:
		return "inner list"
	}
	return "no value"
}

// Value is one item or inner list, with the parameters that followed it.
type Value struct {
	Kind   Kind
	Offset int     // byte offset the value starts at
	Str    string  // text of a String or a Token
	Int    int64   // value of an Integer
	Bytes  []byte  // decoded bytes of a Byte Sequence
	Bool   bool    // value of a Boolean
	Items  []Value // members of an Inner List, each with its own parameters
	Params Params
}

// Param is one parameter of a value.
type Param struct {
	Key   string
	Value Value
}

// Params are the parameters of a value, in input order. A key given twice
// keeps its first position and its last value.
type Params []Param

// Get returns the parameter with the given key.
func (p Params) Get(key string) (Value, bool) {
	for _, param := range p {
		if param.Key == key {
			return param.Value, true
		}
	}
	return Value{}, false
}

func (p Params) set(key string, v Value) Params {
	for i := range p {
		if p[i].Key == key {
			p[i].Value = v
			return p
		}
	}
	return append(p, Param{Key: key, Value: v})
}

// Member is one member of a dictionary.
type Member struct {
	Key   string
	Value Value
}

// Dictionary is a parsed dictionary, in input order.
type Dictionary []Member

// Get returns the member with the given key.
func (d Dictionary) Get(key string) (Value, bool) {
	for _, m := range d {
		if m.Key == key {
			return m.Value, true
		}
	}
	return Value{}, false
}

func (d Dictionary) set(key string, v Value) Dictionary {
	for i := range d {
		if d[i].Key == key {
			d[i].Value = v
			return d
		}
	}
	return append(d, Member{Key: key, Value: v})
}

// SyntaxError is input the parser refused, with the byte offset it was refused
// at. The offset never points past the end of the input.
type SyntaxError struct {
	Offset int
	Msg    string
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("sfv: offset %d: %s", e.Offset, e.Msg)
}

type parser struct {
	in  string
	pos int
}

// ParseDictionary parses a dictionary field value. A value holding nothing but
// whitespace is the empty dictionary rather than an error, so every error this
// function returns names an offset inside the input.
func ParseDictionary(field string) (Dictionary, error) {
	p := &parser{in: field}
	p.skipOWS()
	var d Dictionary
	for p.pos < len(p.in) {
		keyAt := p.pos
		key, err := p.key()
		if err != nil {
			return nil, err
		}
		v := Value{Kind: KindBoolean, Offset: keyAt, Bool: true}
		if p.peek() == '=' {
			p.pos++
			if v, err = p.itemOrInnerList(); err != nil {
				return nil, err
			}
		} else if v.Params, err = p.params(); err != nil {
			return nil, err
		}
		d = d.set(key, v)
		p.skipOWS()
		if p.pos == len(p.in) {
			return d, nil
		}
		if c := p.in[p.pos]; c != ',' {
			return nil, p.failAt(p.pos, "expected , between dictionary members, found %s", describe(c))
		}
		p.pos++
		p.skipOWS()
		if p.pos == len(p.in) {
			return nil, p.failAt(p.pos, "the dictionary ends with a trailing comma")
		}
	}
	return d, nil
}

// ParseItem parses a field value holding a single item with its parameters.
func ParseItem(field string) (Value, error) {
	p := &parser{in: field}
	p.skipOWS()
	v, err := p.item()
	if err != nil {
		return Value{}, err
	}
	p.skipOWS()
	if p.pos != len(p.in) {
		return Value{}, p.failAt(p.pos, "expected the end of the item, found %s", describe(p.in[p.pos]))
	}
	return v, nil
}

func (p *parser) itemOrInnerList() (Value, error) {
	if p.peek() == '(' {
		return p.innerList()
	}
	return p.item()
}

func (p *parser) item() (Value, error) {
	v, err := p.bareItem()
	if err != nil {
		return Value{}, err
	}
	if v.Params, err = p.params(); err != nil {
		return Value{}, err
	}
	return v, nil
}

func (p *parser) innerList() (Value, error) {
	v := Value{Kind: KindInnerList, Offset: p.pos}
	p.pos++
	for {
		p.skipSP()
		if p.pos >= len(p.in) {
			return Value{}, p.failAt(v.Offset, "the inner list opened here is never closed")
		}
		if p.in[p.pos] == ')' {
			p.pos++
			params, err := p.params()
			if err != nil {
				return Value{}, err
			}
			v.Params = params
			return v, nil
		}
		member, err := p.item()
		if err != nil {
			return Value{}, err
		}
		v.Items = append(v.Items, member)
		if p.pos < len(p.in) && p.in[p.pos] != ' ' && p.in[p.pos] != ')' {
			return Value{}, p.failAt(p.pos, "expected a space or ) after an inner list member, found %s", describe(p.in[p.pos]))
		}
	}
}

func (p *parser) params() (Params, error) {
	var ps Params
	for p.pos < len(p.in) && p.in[p.pos] == ';' {
		p.pos++
		p.skipSP()
		keyAt := p.pos
		key, err := p.key()
		if err != nil {
			return nil, err
		}
		v := Value{Kind: KindBoolean, Offset: keyAt, Bool: true}
		if p.pos < len(p.in) && p.in[p.pos] == '=' {
			p.pos++
			if v, err = p.bareItem(); err != nil {
				return nil, err
			}
		}
		ps = ps.set(key, v)
	}
	return ps, nil
}

func (p *parser) key() (string, error) {
	if p.pos >= len(p.in) {
		return "", p.failAt(p.pos, "expected a key, found the end of the input")
	}
	c := p.in[p.pos]
	if !isLCAlpha(c) && c != '*' {
		return "", p.failAt(p.pos, "a key starts with a lowercase letter or *, found %s", describe(c))
	}
	start := p.pos
	p.pos++
	for p.pos < len(p.in) && isKeyByte(p.in[p.pos]) {
		p.pos++
	}
	return p.in[start:p.pos], nil
}

func (p *parser) bareItem() (Value, error) {
	if p.pos >= len(p.in) {
		return Value{}, p.failAt(p.pos, "expected a value, found the end of the input")
	}
	switch c := p.in[p.pos]; {
	case c == '-' || isDigit(c):
		return p.integer()
	case c == '"':
		return p.text()
	case c == ':':
		return p.byteSequence()
	case c == '?':
		return p.boolean()
	case c == '*' || isAlpha(c):
		return p.token()
	case c == '@':
		return Value{}, p.failAt(p.pos, "a date is outside the RFC 9651 subset this parser reads")
	case c == '%':
		return Value{}, p.failAt(p.pos, "a display string is outside the RFC 9651 subset this parser reads")
	default:
		return Value{}, p.failAt(p.pos, "%s begins no RFC 9651 value", describe(c))
	}
}

func (p *parser) integer() (Value, error) {
	start := p.pos
	if p.in[p.pos] == '-' {
		p.pos++
	}
	digits := 0
	for p.pos < len(p.in) && isDigit(p.in[p.pos]) {
		p.pos++
		digits++
	}
	if digits == 0 {
		return Value{}, p.failAt(start, "expected the digits of an integer")
	}
	if p.pos < len(p.in) && p.in[p.pos] == '.' {
		return Value{}, p.failAt(p.pos, "a decimal is outside the RFC 9651 subset this parser reads")
	}
	if digits > 15 {
		return Value{}, p.failAt(start, "an integer takes at most 15 digits, found %d", digits)
	}
	n, err := strconv.ParseInt(p.in[start:p.pos], 10, 64)
	if err != nil {
		return Value{}, p.failAt(start, "%q is not an integer", p.in[start:p.pos])
	}
	return Value{Kind: KindInteger, Offset: start, Int: n}, nil
}

func (p *parser) text() (Value, error) {
	start := p.pos
	p.pos++
	var b strings.Builder
	for p.pos < len(p.in) {
		c := p.in[p.pos]
		p.pos++
		switch {
		case c == '\\':
			if p.pos >= len(p.in) {
				return Value{}, p.failAt(p.pos, "the input ends inside a string escape")
			}
			esc := p.in[p.pos]
			p.pos++
			if esc != '"' && esc != '\\' {
				return Value{}, p.failAt(p.pos-1, `a string escapes only " and \, found %s`, describe(esc))
			}
			b.WriteByte(esc)
		case c == '"':
			return Value{Kind: KindString, Offset: start, Str: b.String()}, nil
		case c < ' ' || c >= 0x7f:
			return Value{}, p.failAt(p.pos-1, "a string holds printable ASCII only, found %s", describe(c))
		default:
			b.WriteByte(c)
		}
	}
	return Value{}, p.failAt(start, "the string opened here is never closed")
}

func (p *parser) byteSequence() (Value, error) {
	start := p.pos
	end := strings.IndexByte(p.in[start+1:], ':')
	if end < 0 {
		return Value{}, p.failAt(start, "the byte sequence opened here is never closed")
	}
	encoded := p.in[start+1 : start+1+end]
	p.pos = start + end + 2
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return Value{}, p.failAt(start+1, "%q is not base64 (%v)", encoded, err)
	}
	return Value{Kind: KindByteSequence, Offset: start, Bytes: data}, nil
}

func (p *parser) boolean() (Value, error) {
	start := p.pos
	p.pos++
	if p.pos >= len(p.in) {
		return Value{}, p.failAt(start, "a boolean is ?0 or ?1, the input ends after ?")
	}
	c := p.in[p.pos]
	p.pos++
	switch c {
	case '0':
		return Value{Kind: KindBoolean, Offset: start}, nil
	case '1':
		return Value{Kind: KindBoolean, Offset: start, Bool: true}, nil
	}
	return Value{}, p.failAt(p.pos-1, "a boolean is ?0 or ?1, found %s", describe(c))
}

func (p *parser) token() (Value, error) {
	start := p.pos
	p.pos++
	for p.pos < len(p.in) && isTokenByte(p.in[p.pos]) {
		p.pos++
	}
	return Value{Kind: KindToken, Offset: start, Str: p.in[start:p.pos]}, nil
}

func (p *parser) peek() byte {
	if p.pos < len(p.in) {
		return p.in[p.pos]
	}
	return 0
}

func (p *parser) skipSP() {
	for p.pos < len(p.in) && p.in[p.pos] == ' ' {
		p.pos++
	}
}

func (p *parser) skipOWS() {
	for p.pos < len(p.in) && (p.in[p.pos] == ' ' || p.in[p.pos] == '\t') {
		p.pos++
	}
}

// failAt keeps the reported offset inside the input, so an error at the end of
// a field names its last byte rather than a position nobody can quote.
func (p *parser) failAt(off int, format string, args ...any) error {
	if off >= len(p.in) {
		off = len(p.in) - 1
	}
	if off < 0 {
		off = 0
	}
	return &SyntaxError{Offset: off, Msg: fmt.Sprintf(format, args...)}
}

func describe(c byte) string {
	if c > ' ' && c < 0x7f {
		return strconv.QuoteRune(rune(c))
	}
	return fmt.Sprintf("byte %#02x", c)
}

func isAlpha(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isLCAlpha(c byte) bool {
	return c >= 'a' && c <= 'z'
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isKeyByte(c byte) bool {
	if isLCAlpha(c) || isDigit(c) {
		return true
	}
	return c == '_' || c == '-' || c == '.' || c == '*'
}

func isTokenByte(c byte) bool {
	if isAlpha(c) || isDigit(c) {
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~:/", c) >= 0
}
