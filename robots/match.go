package robots

import "strings"

const hexDigits = "0123456789ABCDEF"

// Match returns the rule that decides access to path. Per RFC 9309, Section
// 2.2.2, the matching rule with the most octets wins, an allow rule wins a tie
// against a disallow rule of equal length, and among equal rules of the same
// kind the earlier line wins. ok is false when no rule applies, which leaves
// the path allowed; /robots.txt is always allowed.
func (g Group) Match(path string) (rule Rule, ok bool) {
	p := normalize(path)
	if p == "/robots.txt" {
		return Rule{}, false
	}
	best := -1
	for _, r := range g.Rules {
		pattern := normalize(r.Pattern)
		if pattern == "" || !matches(pattern, p) {
			continue
		}
		if n := len(pattern); n > best || (n == best && r.Kind == Allow && rule.Kind == Disallow) {
			rule, best = r, n
		}
	}
	return rule, best >= 0
}

// matches reports whether a normalized pattern matches a normalized path: '*'
// stands for any sequence of octets and a trailing '$' anchors the end.
func matches(pattern, path string) bool {
	anchored := strings.HasSuffix(pattern, "$")
	if anchored {
		pattern = pattern[:len(pattern)-1]
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		if anchored {
			return path == pattern
		}
		return strings.HasPrefix(path, pattern)
	}
	if !strings.HasPrefix(path, parts[0]) {
		return false
	}
	pos := len(parts[0])
	for _, part := range parts[1 : len(parts)-1] {
		i := strings.Index(path[pos:], part)
		if i < 0 {
			return false
		}
		pos += i + len(part)
	}
	last := parts[len(parts)-1]
	if anchored {
		return len(path)-pos >= len(last) && strings.HasSuffix(path, last)
	}
	return strings.Contains(path[pos:], last)
}

// normalize rewrites a path or pattern into the form compared by RFC 9309,
// Section 2.2.2: escapes of unreserved characters are decoded, every other
// escape is uppercased, and octets outside printable US-ASCII are escaped.
func normalize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '%':
			if v, ok := unescape(s[i:]); ok {
				if unreserved(v) {
					b.WriteByte(v)
				} else {
					writeEscape(&b, v)
				}
				i += 3
				continue
			}
			writeEscape(&b, '%')
			i++
		case c <= ' ' || c >= 0x7f:
			writeEscape(&b, c)
			i++
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

func unescape(s string) (byte, bool) {
	if len(s) < 3 {
		return 0, false
	}
	hi, hiOK := unhex(s[1])
	lo, loOK := unhex(s[2])
	if !hiOK || !loOK {
		return 0, false
	}
	return hi<<4 | lo, true
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func unreserved(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return c == '-' || c == '.' || c == '_' || c == '~'
}

func writeEscape(b *strings.Builder, c byte) {
	b.WriteByte('%')
	b.WriteByte(hexDigits[c>>4])
	b.WriteByte(hexDigits[c&0xf])
}
