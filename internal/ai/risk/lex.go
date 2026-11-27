package risk

import "strings"

// word is one shell word after quote removal. Expansions are not performed;
// they are recorded so the classifier can reason about what is unknown.
type word struct {
	text     string
	quoted   bool   // some part was quoted or escaped
	hasVar   bool   // contains a variable / parameter / arithmetic expansion
	unqVar   bool   // some variable expansion was outside double quotes
	subst    bool   // contains a command or process substitution
	glob     bool   // contains an unquoted * ? [
	indirect bool   // contains ${!x}
	guarded  bool   // contains ${x:?...}
	fdPrefix bool   // lexer-only: all digits directly followed by < or >
	tail     string // literal text after the last variable expansion
	quoteAt  int    // index in text where quoting first started, or -1
}

// dyn reports whether the value is not known from the text alone.
func (w word) dyn() bool { return w.hasVar || w.subst }

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func validIdent(s string) bool {
	if s == "" || !isIdentStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isIdentStart(s[i]) && !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// isAssign reports whether the word has the form NAME=value (or NAME+=value)
// with an unquoted name.
func (w word) isAssign() bool {
	eq := strings.IndexByte(w.text, '=')
	if eq <= 0 || (w.quoteAt >= 0 && eq >= w.quoteAt) {
		return false
	}
	name := w.text[:eq]
	name = strings.TrimSuffix(name, "+")
	return validIdent(name)
}

type redir struct {
	op     string // > >> >| &> &>> >& <> < << <<- <<< <&
	fd     string
	target word
}

type cmd struct {
	words   []word
	redirs  []redir
	nameIdx int  // words[:nameIdx] are assignments and reserved words
	noexec  bool // for/case/[[ ... : words are data, not a command
	heredoc string
}

type hereDoc struct {
	c      *cmd
	delim  string
	strip  bool
	quoted bool
}

var reserved = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "fi": true,
	"while": true, "until": true, "do": true, "done": true, "esac": true,
	"{": true, "}": true, "!": true, "coproc": true,
}

type parser struct {
	s         *state
	src       string
	pos       int
	depth     int
	acc       acc
	err       string
	pipes     [][]*cmd
	pending   []hereDoc
	funcs     map[string]bool
	parens    int
	caseDepth int
	casePat   bool
	dbl       bool
}

func (p *parser) fail(msg string) {
	if p.err == "" {
		p.err = msg
	}
}

// sub analyzes the body of a command or process substitution.
func (p *parser) sub(inner string) {
	r := p.s.analyze(inner, p.depth+1)
	if r.approvalReason != "" {
		p.acc.recordApproval("inside command substitution: " + r.approvalReason)
	}
	if r.level == Low {
		return
	}
	lvl := r.level
	if lvl < High {
		lvl = High
	}
	for _, e := range r.es {
		p.acc.add(lvl, "inside command substitution: "+e.why, e.safer)
	}
}

// scanText finds command substitutions inside text that is not split into
// words (here-document bodies, parameter expansions, arithmetic).
func (p *parser) scanText(text string) {
	n := len(text)
	for i := 0; i < n && p.err == ""; {
		switch text[i] {
		case '\\':
			i += 2
		case '`':
			j := backtickEnd(text, i+1)
			if j < 0 {
				p.fail("unterminated backquote")
				return
			}
			p.sub(unescapeBacktick(text[i+1 : j]))
			i = j + 1
		case '$':
			if i+1 < n && text[i+1] == '(' {
				j, ok := scanClose(text, i+2, ')', 0)
				if !ok {
					p.fail("unterminated command substitution")
					return
				}
				inner := text[i+2 : j]
				if strings.HasPrefix(inner, "(") && strings.HasSuffix(inner, ")") {
					p.scanText(inner)
				} else {
					p.sub(inner)
				}
				i = j + 1
			} else {
				i++
			}
		default:
			i++
		}
	}
}

func backtickEnd(s string, i int) int {
	for i < len(s) {
		switch s[i] {
		case '\\':
			i += 2
		case '`':
			return i
		default:
			i++
		}
	}
	return -1
}

func unescapeBacktick(s string) string {
	if strings.IndexByte(s, '\\') < 0 {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '`' || s[i+1] == '\\' || s[i+1] == '$') {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// scanClose returns the index of the closer that ends a construct whose
// contents start at i, skipping quotes and nested constructs.
func scanClose(s string, i int, closer byte, depth int) (int, bool) {
	if depth > 24 {
		return 0, false
	}
	n := len(s)
	for i < n {
		c := s[i]
		switch c {
		case '\\':
			i += 2
		case '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return 0, false
			}
			i += j + 2
		case '"':
			j, ok := scanDQ(s, i+1, depth+1)
			if !ok {
				return 0, false
			}
			i = j + 1
		case '`':
			j := backtickEnd(s, i+1)
			if j < 0 {
				return 0, false
			}
			i = j + 1
		case '$':
			switch {
			case i+1 < n && s[i+1] == '(':
				j, ok := scanClose(s, i+2, ')', depth+1)
				if !ok {
					return 0, false
				}
				i = j + 1
			case i+1 < n && s[i+1] == '{':
				j, ok := scanClose(s, i+2, '}', depth+1)
				if !ok {
					return 0, false
				}
				i = j + 1
			case i+1 < n && s[i+1] == '\'':
				i += 2
				for i < n && s[i] != '\'' {
					if s[i] == '\\' {
						i++
					}
					i++
				}
				i++
			default:
				i++
			}
		case '(':
			if closer == ')' {
				j, ok := scanClose(s, i+1, ')', depth+1)
				if !ok {
					return 0, false
				}
				i = j + 1
			} else {
				i++
			}
		case '#':
			if closer == ')' && (i == 0 || strings.IndexByte(" \t\n;(", s[i-1]) >= 0) {
				for i < n && s[i] != '\n' {
					i++
				}
			} else {
				i++
			}
		default:
			if c == closer {
				return i, true
			}
			i++
		}
	}
	return 0, false
}

func scanDQ(s string, i, depth int) (int, bool) {
	if depth > 24 {
		return 0, false
	}
	n := len(s)
	for i < n {
		switch s[i] {
		case '\\':
			i += 2
		case '"':
			return i, true
		case '`':
			j := backtickEnd(s, i+1)
			if j < 0 {
				return 0, false
			}
			i = j + 1
		case '$':
			switch {
			case i+1 < n && s[i+1] == '(':
				j, ok := scanClose(s, i+2, ')', depth+1)
				if !ok {
					return 0, false
				}
				i = j + 1
			case i+1 < n && s[i+1] == '{':
				j, ok := scanClose(s, i+2, '}', depth+1)
				if !ok {
					return 0, false
				}
				i = j + 1
			default:
				i++
			}
		default:
			i++
		}
	}
	return 0, false
}

// wb builds one word.
type wb struct {
	w         word
	sb        strings.Builder
	tailStart int
}

func newWB() *wb { return &wb{w: word{quoteAt: -1}} }

func (b *wb) quote() {
	if b.w.quoteAt < 0 {
		b.w.quoteAt = b.sb.Len()
	}
	b.w.quoted = true
}

func (b *wb) variable(raw string, inDQ bool) {
	b.sb.WriteString(raw)
	b.tailStart = b.sb.Len()
	b.w.hasVar = true
	if !inDQ {
		b.w.unqVar = true
	}
}

func (b *wb) finish() word {
	b.w.text = b.sb.String()
	if b.w.text == "[" || b.w.text == "[[" {
		b.w.glob = false
	}
	if b.tailStart <= len(b.w.text) {
		b.w.tail = b.w.text[b.tailStart:]
	}
	return b.w
}

func isSpecialParam(c byte) bool { return strings.IndexByte("@*#?!$-", c) >= 0 }

// readDollar handles a $ at p.pos. inDQ is true inside double quotes.
func (p *parser) readDollar(b *wb, inDQ bool) bool {
	n := len(p.src)
	if p.pos+1 >= n {
		b.sb.WriteByte('$')
		p.pos++
		return true
	}
	d := p.src[p.pos+1]
	switch {
	case d == '(':
		end, ok := scanClose(p.src, p.pos+2, ')', 0)
		if !ok {
			p.fail("unterminated command substitution")
			return false
		}
		inner := p.src[p.pos+2 : end]
		if strings.HasPrefix(inner, "(") && strings.HasSuffix(inner, ")") {
			p.scanText(inner)
			b.variable("$((0))", inDQ)
		} else {
			p.sub(inner)
			b.w.subst = true
			b.sb.WriteString("$()")
			b.tailStart = b.sb.Len()
		}
		p.pos = end + 1
	case d == '{':
		end, ok := scanClose(p.src, p.pos+2, '}', 0)
		if !ok {
			p.fail("unterminated parameter expansion")
			return false
		}
		inner := p.src[p.pos+2 : end]
		p.scanText(inner)
		if strings.HasPrefix(inner, "!") {
			b.w.indirect = true
		}
		if strings.Contains(inner, ":?") {
			b.w.guarded = true
		}
		b.variable("${"+inner+"}", inDQ)
		p.pos = end + 1
	case d == '\'' && !inDQ:
		p.pos += 2
		b.quote()
		for p.pos < n && p.src[p.pos] != '\'' {
			c := p.src[p.pos]
			if c == '\\' && p.pos+1 < n {
				p.pos++
				p.ansiEscape(b)
				continue
			}
			b.sb.WriteByte(c)
			p.pos++
		}
		if p.pos >= n {
			p.fail("unterminated $'...' string")
			return false
		}
		p.pos++
	case d == '"' && !inDQ:
		p.pos++ // the quote is read by the caller's loop
	case isIdentStart(d):
		j := p.pos + 1
		for j < n && (isIdentStart(p.src[j]) || isDigit(p.src[j])) {
			j++
		}
		b.variable(p.src[p.pos:j], inDQ)
		p.pos = j
	case isDigit(d) || isSpecialParam(d):
		b.variable(p.src[p.pos:p.pos+2], inDQ)
		p.pos += 2
	default:
		b.sb.WriteByte('$')
		p.pos++
	}
	return true
}

// ansiEscape decodes the escape at p.pos (after the backslash) in $'...'.
func (p *parser) ansiEscape(b *wb) {
	n := len(p.src)
	c := p.src[p.pos]
	switch c {
	case 'n':
		b.sb.WriteByte('\n')
		p.pos++
	case 't':
		b.sb.WriteByte('\t')
		p.pos++
	case 'r':
		b.sb.WriteByte('\r')
		p.pos++
	case 'a':
		b.sb.WriteByte(7)
		p.pos++
	case 'e', 'E':
		b.sb.WriteByte(27)
		p.pos++
	case 'x':
		v, k := 0, 0
		p.pos++
		for k < 2 && p.pos < n && hexVal(p.src[p.pos]) >= 0 {
			v = v*16 + hexVal(p.src[p.pos])
			p.pos++
			k++
		}
		b.sb.WriteByte(byte(v))
	case '0', '1', '2', '3', '4', '5', '6', '7':
		v, k := 0, 0
		for k < 3 && p.pos < n && p.src[p.pos] >= '0' && p.src[p.pos] <= '7' {
			v = v*8 + int(p.src[p.pos]-'0')
			p.pos++
			k++
		}
		b.sb.WriteByte(byte(v))
	default:
		b.sb.WriteByte(c)
		p.pos++
	}
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func (p *parser) readBacktick(b *wb) bool {
	j := backtickEnd(p.src, p.pos+1)
	if j < 0 {
		p.fail("unterminated backquote")
		return false
	}
	p.sub(unescapeBacktick(p.src[p.pos+1 : j]))
	b.w.subst = true
	b.sb.WriteString("$()")
	b.tailStart = b.sb.Len()
	p.pos = j + 1
	return true
}

func (p *parser) readDQ(b *wb) bool {
	n := len(p.src)
	p.pos++
	b.quote()
	for p.pos < n {
		c := p.src[p.pos]
		switch c {
		case '"':
			p.pos++
			return true
		case '\\':
			if p.pos+1 < n {
				switch d := p.src[p.pos+1]; d {
				case '$', '`', '"', '\\':
					b.sb.WriteByte(d)
					p.pos += 2
					continue
				case '\n':
					p.pos += 2
					continue
				}
			}
			b.sb.WriteByte('\\')
			p.pos++
		case '$':
			if !p.readDollar(b, true) {
				return false
			}
		case '`':
			if !p.readBacktick(b) {
				return false
			}
		default:
			b.sb.WriteByte(c)
			p.pos++
		}
	}
	p.fail("unterminated double quote")
	return false
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// readWord reads one word starting at p.pos. The returned word may be empty
// when the next character is an operator.
func (p *parser) readWord() (word, bool) {
	b := newWB()
	n := len(p.src)
loop:
	for p.pos < n {
		c := p.src[p.pos]
		switch c {
		case ' ', '\t', '\n', '\r':
			break loop
		case ';':
			break loop
		case '&', '|', ')':
			if p.dbl {
				b.sb.WriteByte(c)
				p.pos++
				continue
			}
			break loop
		case '(':
			if p.dbl {
				b.sb.WriteByte(c)
				p.pos++
				continue
			}
			cur := b.sb.String()
			if strings.HasSuffix(cur, "=") && b.w.quoteAt < 0 && validIdent(strings.TrimSuffix(strings.TrimSuffix(cur, "="), "+")) {
				// array assignment: NAME=( ... )
				end, ok := scanClose(p.src, p.pos+1, ')', 0)
				if !ok {
					p.fail("unterminated array assignment")
					return word{}, false
				}
				p.scanText(p.src[p.pos+1 : end])
				b.sb.WriteString(p.src[p.pos : end+1])
				p.pos = end + 1
				continue
			}
			break loop
		case '<', '>':
			if p.pos+1 < n && p.src[p.pos+1] == '(' {
				end, ok := scanClose(p.src, p.pos+2, ')', 0)
				if !ok {
					p.fail("unterminated process substitution")
					return word{}, false
				}
				p.sub(p.src[p.pos+2 : end])
				b.w.subst = true
				b.sb.WriteString("<()")
				b.tailStart = b.sb.Len()
				p.pos = end + 1
				continue
			}
			if p.dbl {
				b.sb.WriteByte(c)
				p.pos++
				continue
			}
			if b.sb.Len() > 0 && !b.w.quoted && allDigits(b.sb.String()) {
				b.w.fdPrefix = true
			}
			break loop
		case '\\':
			if p.pos+1 >= n {
				b.sb.WriteByte('\\')
				p.pos++
				continue
			}
			d := p.src[p.pos+1]
			if d == '\n' {
				p.pos += 2
				continue
			}
			if d == '\r' && p.pos+2 < n && p.src[p.pos+2] == '\n' {
				p.pos += 3
				continue
			}
			b.quote()
			b.sb.WriteByte(d)
			p.pos += 2
		case '\'':
			j := strings.IndexByte(p.src[p.pos+1:], '\'')
			if j < 0 {
				p.fail("unterminated single quote")
				return word{}, false
			}
			b.quote()
			b.sb.WriteString(p.src[p.pos+1 : p.pos+1+j])
			p.pos += j + 2
		case '"':
			if !p.readDQ(b) {
				return word{}, false
			}
		case '$':
			if !p.readDollar(b, false) {
				return word{}, false
			}
		case '`':
			if !p.readBacktick(b) {
				return word{}, false
			}
		case '*', '?', '[':
			b.w.glob = true
			b.sb.WriteByte(c)
			p.pos++
		default:
			b.sb.WriteByte(c)
			p.pos++
		}
	}
	return b.finish(), true
}

func (p *parser) skipBlanks() {
	n := len(p.src)
	for p.pos < n {
		c := p.src[p.pos]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			p.pos++
		case c == '\\' && p.pos+1 < n && p.src[p.pos+1] == '\n':
			p.pos += 2
		default:
			return
		}
	}
}

func (p *parser) readRedirect(cur *cmd, fd string) {
	rest := p.src[p.pos:]
	op := ""
	for _, cand := range []string{"&>>", "&>", "<<<", "<<-", "<<", "<&", "<>", ">>", ">|", ">&", ">", "<"} {
		if strings.HasPrefix(rest, cand) {
			op = cand
			break
		}
	}
	if op == "" {
		p.fail("bad redirection")
		return
	}
	p.pos += len(op)
	p.skipBlanks()
	w, ok := p.readWord()
	if !ok {
		return
	}
	if w.text == "" && !w.quoted {
		p.fail("missing redirection target")
		return
	}
	if op == "<<" || op == "<<-" {
		p.pending = append(p.pending, hereDoc{c: cur, delim: w.text, strip: op == "<<-", quoted: w.quoted})
	}
	cur.redirs = append(cur.redirs, redir{op: op, fd: fd, target: w})
}

func (p *parser) readHeredocs() {
	for _, h := range p.pending {
		var body strings.Builder
		found := false
		for p.pos < len(p.src) {
			j := strings.IndexByte(p.src[p.pos:], '\n')
			var line string
			if j < 0 {
				line = p.src[p.pos:]
				p.pos = len(p.src)
			} else {
				line = p.src[p.pos : p.pos+j]
				p.pos += j + 1
			}
			cmp := strings.TrimSuffix(line, "\r")
			if h.strip {
				cmp = strings.TrimLeft(cmp, "\t")
			}
			if cmp == h.delim {
				found = true
				break
			}
			body.WriteString(line)
			body.WriteByte('\n')
		}
		if !found {
			p.fail("unterminated here-document")
		}
		h.c.heredoc += body.String()
		if !h.quoted {
			p.scanText(body.String())
		}
	}
	p.pending = nil
}

// readCasePattern consumes "pat1 | pat2 )" at the start of a case arm.
func (p *parser) readCasePattern() {
	p.casePat = false
	p.skipBlanks()
	for p.pos < len(p.src) && p.err == "" {
		p.skipBlanks()
		if p.pos >= len(p.src) {
			break
		}
		c := p.src[p.pos]
		switch c {
		case '\n':
			p.pos++
			p.casePat = true // blank lines before the first arm
			p.readHeredocs()
			return
		case ')':
			p.pos++
			return
		case '|', '(':
			p.pos++
			continue
		}
		if strings.HasPrefix(p.src[p.pos:], "esac") {
			e := p.pos + 4
			if e >= len(p.src) || strings.IndexByte(" \t\n;", p.src[e]) >= 0 {
				if p.caseDepth > 0 {
					p.caseDepth--
				}
				p.pos = e
				return
			}
		}
		before := p.pos
		_, ok := p.readWord()
		if !ok {
			return
		}
		if p.pos == before {
			p.fail("unexpected character in case pattern")
			return
		}
	}
}

func (p *parser) addWord(cur *cmd, w word) (flush bool) {
	cur.words = append(cur.words, w)
	if p.dbl && w.text == "]]" && !w.quoted {
		p.dbl = false
	}
	if cur.nameIdx == len(cur.words)-1 {
		if w.isAssign() || (!w.quoted && reserved[w.text]) {
			cur.nameIdx++
			if w.text == "esac" && !w.quoted && p.caseDepth > 0 {
				p.caseDepth--
			}
			return false
		}
		if !w.quoted {
			switch w.text {
			case "[[":
				p.dbl = true
				cur.noexec = true
			case "case", "for", "select", "function":
				cur.noexec = true
			}
		}
		return false
	}
	nm := cur.nameIdx
	if nm < len(cur.words) && cur.words[nm].text == "function" && len(cur.words) == nm+2 {
		if p.funcs == nil {
			p.funcs = map[string]bool{}
		}
		p.funcs[w.text] = true
		return true
	}
	if nm < len(cur.words) && cur.words[nm].text == "case" && !cur.words[nm].quoted &&
		len(cur.words) == nm+3 && w.text == "in" && !w.quoted {
		p.caseDepth++
		p.casePat = true
		return true
	}
	return false
}

func (p *parser) run() {
	cur := &cmd{}
	var pipe []*cmd
	lastPipe := false
	flush := func(keep bool) {
		if len(cur.words) > 0 || len(cur.redirs) > 0 {
			pipe = append(pipe, cur)
		}
		cur = &cmd{}
		if !keep && len(pipe) > 0 {
			p.pipes = append(p.pipes, pipe)
			pipe = nil
		}
		lastPipe = keep
	}
	n := len(p.src)
	for p.err == "" {
		p.skipBlanks()
		if p.pos >= n {
			break
		}
		c := p.src[p.pos]
		atStart := len(cur.words) == 0 && len(cur.redirs) == 0
		if p.casePat && atStart {
			p.readCasePattern()
			continue
		}
		if p.dbl && c == '\n' {
			p.pos++
			continue
		}
		if !p.dbl {
			rest := p.src[p.pos:]
			switch c {
			case '#':
				for p.pos < n && p.src[p.pos] != '\n' {
					p.pos++
				}
				continue
			case '\n':
				p.pos++
				p.readHeredocs()
				if !lastPipe || len(cur.words) > 0 || len(cur.redirs) > 0 {
					flush(false)
				}
				continue
			case ';':
				p.pos++
				arm := false
				if p.pos < n && p.src[p.pos] == ';' {
					p.pos++
					arm = true
					if p.pos < n && p.src[p.pos] == '&' {
						p.pos++
					}
				} else if p.pos < n && p.src[p.pos] == '&' {
					p.pos++
					arm = true
				}
				flush(false)
				if arm && p.caseDepth > 0 {
					p.casePat = true
				}
				continue
			case '&':
				if strings.HasPrefix(rest, "&&") {
					p.pos += 2
					flush(false)
					continue
				}
				if strings.HasPrefix(rest, "&>") {
					p.readRedirect(cur, "")
					continue
				}
				p.pos++
				flush(false)
				continue
			case '|':
				switch {
				case strings.HasPrefix(rest, "||"):
					p.pos += 2
					flush(false)
				case strings.HasPrefix(rest, "|&"):
					p.pos += 2
					flush(true)
				default:
					p.pos++
					flush(true)
				}
				continue
			case '(':
				if atStart && strings.HasPrefix(rest, "((") {
					end, ok := scanClose(p.src, p.pos+1, ')', 0)
					if !ok {
						p.fail("unterminated (( ))")
						continue
					}
					p.scanText(p.src[p.pos+1 : end])
					p.pos = end + 1
					continue
				}
				if len(cur.words) == 1 && len(cur.redirs) == 0 {
					q := p.pos + 1
					for q < n && (p.src[q] == ' ' || p.src[q] == '\t') {
						q++
					}
					if q < n && p.src[q] == ')' {
						if p.funcs == nil {
							p.funcs = map[string]bool{}
						}
						p.funcs[cur.words[0].text] = true
						cur = &cmd{}
						p.pos = q + 1
						continue
					}
				}
				p.pos++
				p.parens++
				flush(false)
				continue
			case ')':
				p.pos++
				p.parens--
				if p.parens < 0 {
					if p.caseDepth > 0 {
						p.parens = 0
					} else {
						p.fail("unbalanced )")
					}
				}
				flush(false)
				continue
			case '<', '>':
				if !(p.pos+1 < n && p.src[p.pos+1] == '(') {
					p.readRedirect(cur, "")
					continue
				}
			}
		}
		before := p.pos
		w, ok := p.readWord()
		if !ok {
			break
		}
		if w.fdPrefix {
			p.readRedirect(cur, w.text)
			continue
		}
		if p.pos == before {
			p.fail("unexpected character")
			break
		}
		if p.addWord(cur, w) {
			flush(false)
		}
	}
	p.readHeredocs()
	flush(false)
	if p.err == "" && p.parens > 0 {
		p.fail("unbalanced (")
	}
	if p.err == "" && p.dbl {
		p.fail("unterminated [[")
	}
}
