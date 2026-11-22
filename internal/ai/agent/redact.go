package agent

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"motty/internal/ai/llm"
)

var (
	pemBegin = "-----BEGIN "

	// name=value / name: value where name ends in a secret-like word.
	reAssign = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key)(["']?[^\S\n]*[=:][^\S\n]*)("[^"\n]*"|'[^'\n]*'|[^\s"',;&]+)`)
	reFlag   = regexp.MustCompile(`(?i)(--(?:password|passwd|token|secret|api-key)[= ])(\S+)`)
	reBearer = regexp.MustCompile(`(?i)\b(bearer[^\S\n]+)[A-Za-z0-9._~+/=-]{8,}`)
	reBasic  = regexp.MustCompile(`(?i)(authorization[^\S\n]*:[^\S\n]*basic[^\S\n]+)\S+`)
	reAWS    = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
	reJWT    = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*`)
	// Credentials embedded in a URL. The colon form keeps the user name
	// readable (postgres://deploy:***@host); a lone userinfo is a token used
	// as the user name (https://<token>@github.com) and is masked whole.
	// Both require the closing @ so ordinary host:port URLs never match.
	reURLPassword = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s/@:]+):[^\s/@]+@`)
	reURLUser     = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@:]+@`)
	// Well-known vendor token prefixes that carry no spaces.
	reVendorToken = regexp.MustCompile(`\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}|sk_(?:live|test|proj)_[A-Za-z0-9]{16,}|pk_(?:live|test)_[A-Za-z0-9]{16,}|glpat-[A-Za-z0-9_-]{16,})`)
	// A private key flattened onto one line, as configs and JSON carry them:
	// the PEM markers with literal "\n" separators between them.
	reFlatPEM = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----.*-----END [A-Z ]*PRIVATE KEY-----`)
)

const mask = "***"

// Redact masks secrets in text before it is sent to a model: PEM private key
// blocks (every body line becomes [REDACTED], so the line count is kept),
// flattened single-line private keys, password/token/secret/api_key
// assignments, credentials embedded in URLs, well-known vendor token
// prefixes, Bearer and Basic authorization values, AWS access key ids and
// JWT-looking tokens. Ordinary text is returned unchanged and unallocated.
func Redact(text string) string {
	if strings.Contains(text, pemBegin) {
		text = redactPEM(text)
	}
	var out strings.Builder
	changed := false
	for rest := text; rest != ""; {
		line := rest
		if i := strings.IndexByte(rest, '\n'); i >= 0 {
			line, rest = rest[:i+1], rest[i+1:]
		} else {
			rest = ""
		}
		red := redactLine(line)
		if red != line && !changed {
			changed = true
			out.Grow(len(text))
			out.WriteString(text[:len(text)-len(rest)-len(line)])
		}
		if changed {
			out.WriteString(red)
		}
	}
	if changed {
		return out.String()
	}
	return text
}

func modelMessages(messages []llm.Message, redact bool) []llm.Message {
	if !redact {
		return messages
	}
	masked := slices.Clone(messages)
	for index := range masked {
		message := &masked[index]
		message.Text = redactModelText(message.Text)
		message.ToolCalls = slices.Clone(message.ToolCalls)
		for call := range message.ToolCalls {
			message.ToolCalls[call].Arguments = redactJSON(message.ToolCalls[call].Arguments)
		}
	}
	return masked
}

func redactModelText(text string) string {
	if isStructuredJSON(text) {
		return redactJSON(text)
	}
	if end := strings.LastIndexByte(text, '\n') + 1; end > 0 && isStructuredJSON(text[end:]) {
		return Redact(text[:end]) + redactJSON(text[end:])
	}
	return Redact(text)
}

func isStructuredJSON(text string) bool {
	text = strings.TrimSpace(text)
	return len(text) > 0 && (text[0] == '{' || text[0] == '[') && json.Valid([]byte(text))
}

func redactJSON(raw string) string {
	if !json.Valid([]byte(raw)) {
		return Redact(raw)
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "{}"
	}
	value, changed := redactJSONValue(value)
	if !changed {
		return raw
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func redactJSONValue(value any) (any, bool) {
	changed := false
	switch value := value.(type) {
	case string:
		masked := Redact(value)
		return masked, masked != value
	case []any:
		for index, item := range value {
			masked, edited := redactJSONValue(item)
			value[index] = masked
			changed = changed || edited
		}
	case map[string]any:
		for key, item := range value {
			if item != nil && reAssign.MatchString(key+"=x") {
				value[key] = mask
				changed = true
				continue
			}
			masked, edited := redactJSONValue(item)
			value[key] = masked
			changed = changed || edited
		}
	}
	return value, changed
}

// hasFold reports whether s contains the lower-case ASCII word sub, ignoring case.
func hasFold(s, sub string) bool {
	c0, c1 := sub[0], sub[0]-'a'+'A'
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i] != c0 && s[i] != c1 {
			continue
		}
		if strings.EqualFold(s[i:i+len(sub)], sub) {
			return true
		}
	}
	return false
}

func redactPEM(text string) string {
	var b strings.Builder
	for {
		i := strings.Index(text, pemBegin)
		if i < 0 {
			b.WriteString(text)
			return b.String()
		}
		eol := strings.IndexByte(text[i:], '\n')
		header := text[i:]
		if eol >= 0 {
			header = text[i : i+eol]
		}
		if !strings.Contains(header, "PRIVATE KEY-----") {
			b.WriteString(text[:i+len(pemBegin)])
			text = text[i+len(pemBegin):]
			continue
		}
		b.WriteString(text[:i])
		rest := text[i:]
		// The block ends after the END line, or at the end of the text.
		end := len(rest)
		if e := strings.Index(rest, "-----END "); e >= 0 {
			end = e
			if nl := strings.IndexByte(rest[e:], '\n'); nl >= 0 {
				end = e + nl
			} else {
				end = len(rest)
			}
		}
		block := rest[:end]
		for k, line := range strings.Split(block, "\n") {
			if k > 0 {
				b.WriteByte('\n')
			}
			if strings.HasPrefix(line, pemBegin) && strings.Contains(line, "PRIVATE KEY-----") || strings.HasPrefix(line, "-----END ") {
				b.WriteString(line)
			} else {
				b.WriteString("[REDACTED]")
			}
		}
		text = rest[end:]
	}
}

// redactLine applies the single-line rules; the cheap substring checks keep
// ordinary lines away from the regular expressions.
func redactLine(l string) string {
	if hasFold(l, "pass") || hasFold(l, "pwd") || hasFold(l, "secret") || hasFold(l, "token") || hasFold(l, "key") {
		l = reAssign.ReplaceAllString(l, "${1}${2}"+mask)
		l = reFlag.ReplaceAllString(l, "${1}"+mask)
	}
	if hasFold(l, "bearer") {
		l = reBearer.ReplaceAllString(l, "${1}"+mask)
	}
	if hasFold(l, "basic") {
		l = reBasic.ReplaceAllString(l, "${1}"+mask)
	}
	if strings.Contains(l, "AKIA") || strings.Contains(l, "ASIA") {
		l = reAWS.ReplaceAllString(l, "AKIA"+mask)
	}
	if strings.Contains(l, "eyJ") {
		l = reJWT.ReplaceAllString(l, mask)
	}
	if strings.Contains(l, "://") && strings.ContainsRune(l, '@') {
		l = reURLPassword.ReplaceAllString(l, "${1}:"+mask+"@")
		l = reURLUser.ReplaceAllString(l, "${1}"+mask+"@")
	}
	if strings.Contains(l, "PRIVATE KEY-----") && strings.Contains(l, "\\n") {
		l = reFlatPEM.ReplaceAllString(l, mask)
	}
	for _, prefix := range vendorTokenPrefixes {
		if strings.Contains(l, prefix) {
			l = reVendorToken.ReplaceAllString(l, mask)
			break
		}
	}
	return l
}

// vendorTokenPrefixes are the cheap gates for reVendorToken.
var vendorTokenPrefixes = []string{
	"ghp_", "github_pat_", "xox", "AIza", "sk_live_", "sk_test_", "sk_proj_",
	"pk_live_", "pk_test_", "glpat-",
}
