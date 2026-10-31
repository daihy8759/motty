package completion

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// validTokenPart reports whether s can be a command or option name. A token is
// inserted into a shell command line, so it must be a plain bare word.
func validTokenPart(s string) bool {
	if s == "" || len(s) > 64 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		switch {
		case r < utf8.RuneSelf && (unicode.IsLetter(r) || unicode.IsDigit(r)):
		case strings.ContainsRune("-_.:+@%", r):
		default:
			return false
		}
	}
	return true
}

// SafeValue reports whether a literal option value can be inserted as a bare
// word. Quotes, escapes, whitespace, control characters and shell metacharacters
// are rejected: the completion never needs to escape anything, and refusing
// those values keeps it that way.
func SafeValue(s string) bool {
	if s == "" || len(s) > maxValueBytes || !utf8.ValidString(s) {
		return false
	}
	if strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		switch {
		case r >= utf8.RuneSelf:
			// Non-ASCII text is allowed only when it is a letter, digit or
			// common punctuation that no shell treats specially.
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
				return false
			}
		case unicode.IsLetter(r) || unicode.IsDigit(r):
		case strings.ContainsRune("-_.:@%+,=/", r):
		default:
			return false
		}
	}
	return true
}

// normalizeText turns a source description into one bounded line. Empty lines
// and tabs would otherwise leak into the list row and the encoded catalog.
func normalizeText(s string, limit int) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		if r < utf8.RuneSelf && (unicode.IsControl(r) || unicode.IsSpace(r)) {
			space = b.Len() > 0
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	out := b.String()
	if limit > 0 && utf8.RuneCountInString(out) > limit {
		runes := []rune(out)
		out = string(runes[:limit])
	}
	return out
}
