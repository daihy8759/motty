package risk

import "strings"

type state struct {
	budget int
	funcs  map[string]bool // shell functions defined by the scripts being analyzed
}

type stdinKind uint8

const (
	inNone stdinKind = iota
	inPipe
	inFile
	inHere
)

type stdin struct {
	kind stdinKind
	text string // known content that will be fed to the command, if any
}

// call is one simple command whose wrappers have been removed.
type call struct {
	s     *state
	name  string
	args  []word
	in    stdin
	depth int
	label string // name plus the subcommand, for reasons
	subAt int    // index in args of the subcommand, or -1
}

func (c *call) inner(ws []word, a *acc) {
	c.s.words(ws, stdin{}, c.depth+1, a)
}

func (s *state) analyze(src string, depth int) acc {
	var a acc
	if depth > maxDepth {
		a.requireApproval(High, "nesting too deep to review", "Split the command into separate steps")
		return a
	}
	if s.budget--; s.budget < 0 {
		a.requireApproval(High, "command too complex to review", "Split the command into separate steps")
		return a
	}
	p := &parser{s: s, src: src, depth: depth}
	p.run()
	a.merge(p.acc)
	if p.err != "" {
		a.requireApproval(High, "could not parse the command: "+p.err, "Rewrite it as simpler, well-formed commands")
	}
	saved := s.funcs
	if len(p.funcs) > 0 {
		merged := make(map[string]bool, len(saved)+len(p.funcs))
		for k := range saved {
			merged[k] = true
		}
		for k := range p.funcs {
			merged[k] = true
		}
		s.funcs = merged
	}
	defer func() { s.funcs = saved }()
	for _, pl := range p.pipes {
		s.pipeline(pl, depth, &a)
		if len(p.funcs) > 0 && len(pl) >= 2 {
			n := 0
			for _, c := range pl {
				if c.nameIdx < len(c.words) && p.funcs[c.words[c.nameIdx].text] {
					n++
				}
			}
			if n >= 2 {
				a.add(Critical, "fork bomb: a function piped into itself", "")
			}
		}
	}
	return a
}

func feedText(prev *cmd) string {
	text := prev.heredoc
	if prev.nameIdx < len(prev.words) {
		switch baseName(prev.words[prev.nameIdx].text) {
		case "echo", "printf":
			for _, w := range prev.words[prev.nameIdx+1:] {
				if strings.HasPrefix(w.text, "-") && len(w.text) <= 3 {
					continue
				}
				text += " " + w.text
			}
		}
	}
	for _, r := range prev.redirs {
		if r.op == "<<<" {
			text += " " + r.target.text
		}
	}
	return text
}

func (s *state) pipeline(pl []*cmd, depth int, a *acc) {
	for i, c := range pl {
		in := stdin{}
		if i > 0 {
			in = stdin{inPipe, feedText(pl[i-1])}
		}
		for _, r := range c.redirs {
			switch r.op {
			case "<<", "<<-":
				in = stdin{inHere, c.heredoc}
			case "<<<":
				in = stdin{inHere, r.target.text}
			case "<":
				in = stdin{inFile, ""}
			}
		}
		s.command(c, in, depth, a)
	}
}

func (s *state) command(c *cmd, in stdin, depth int, a *acc) {
	for _, r := range c.redirs {
		switch r.op {
		case "<", "<>", "<&":
			a.checkCredential(r.target.text)
		}
		switch r.op {
		case ">", ">>", ">|", "&>", "&>>", "<>":
			s.writeTarget(r.target, "redirection", a)
		case ">&":
			if t := r.target.text; t != "-" && !allDigits(t) {
				s.writeTarget(r.target, "redirection", a)
			}
		}
	}
	for _, w := range c.words[:c.nameIdx] {
		if w.isAssign() {
			assignment(w, a)
		}
	}
	if c.noexec || c.nameIdx >= len(c.words) {
		return
	}
	ws := c.words[c.nameIdx:]
	s.words(ws, in, depth, a)
	for _, w := range ws {
		a.checkCredential(w.text)
	}
}

func (a *acc) checkCredential(text string) {
	if credWord(text) {
		a.requireApproval(Medium, "touches private key or credential material", "")
	}
}

var riskyEnv = set("LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT BASH_ENV ENV PROMPT_COMMAND SHELLOPTS BASHOPTS IFS PS4 PERL5OPT PERL5LIB PYTHONSTARTUP PYTHONPATH NODE_OPTIONS RUBYOPT GIT_SSH_COMMAND GIT_EXTERNAL_DIFF")

func assignment(w word, a *acc) {
	name := strings.TrimSuffix(w.text[:strings.IndexByte(w.text, '=')], "+")
	if riskyEnv[name] {
		a.add(High, "sets "+name+", which can change how commands execute", "")
	}
}

// writeTarget records the effect of writing to the file named by w.
func (s *state) writeTarget(w word, why string, a *acc) {
	t := w.text
	p, _ := normPath(t)
	switch {
	case benignDev(p):
		return
	case p == "/proc/sysrq-trigger":
		a.add(Critical, why+" writes to sysrq-trigger (can crash or reboot the machine)", "")
	case isBlockDev(p):
		a.add(Critical, why+" writes directly to a raw device", "Write to a regular file or image instead")
	case strings.HasPrefix(p, "/dev/"):
		a.add(High, why+" writes to a device node", "")
	case sensitive(p):
		a.add(High, why+" overwrites a security-sensitive file", "Back it up and edit with care; keep a second session open")
	case inSystemTree(p):
		a.add(High, why+" writes under a system directory ("+short(p)+")", "")
	default:
		a.add(Medium, why+" writes to a file", "Print to the terminal instead of writing a file")
	}
	if w.dyn() {
		a.add(Medium, why+" target is computed at run time", "")
	}
}

var (
	shells = set("sh bash zsh dash ksh ash csh tcsh fish mksh rbash rsh")
	interp = set("python python2 python3 pypy pypy3 perl ruby node nodejs php lua luajit deno bun tclsh Rscript julia irb ipython osascript expect")
)

func isInterpreter(name string) bool {
	if interp[name] {
		return true
	}
	for _, pre := range []string{"python3.", "python2.", "perl5.", "ruby3."} {
		if strings.HasPrefix(name, pre) {
			return true
		}
	}
	return false
}

func (s *state) words(ws []word, in stdin, depth int, a *acc) {
	if s.budget--; s.budget < 0 {
		a.requireApproval(High, "command too complex to review", "Split the command into separate steps")
		return
	}
	if depth > maxDepth {
		a.requireApproval(High, "nesting too deep to review", "Split the command into separate steps")
		return
	}
	for len(ws) > 0 && ws[0].isAssign() {
		assignment(ws[0], a)
		ws = ws[1:]
	}
	if len(ws) == 0 {
		return
	}
	n := ws[0]
	args := ws[1:]
	if n.dyn() || n.glob || n.indirect {
		a.requireApproval(High, "command name is built from a variable, glob or substitution (possible obfuscation)", "Write the command name literally")
		for _, w := range args {
			if w.text == "/" || w.text == "/*" || w.text == "~" {
				a.add(Critical, "computed command applied to a filesystem root", "")
				break
			}
		}
		return
	}
	name := baseName(n.text)
	if s.funcs[n.text] && lookupRule(name) == nil && wrappers[name] == nil && !shells[name] && !isInterpreter(name) {
		return // a function defined in the script; its body is classified where it is defined
	}
	if i := strings.Index(n.text, "/init.d/"); i >= 0 {
		args = append([]word{{text: name, quoteAt: -1}}, args...)
		name = "service"
	}
	if index := strings.LastIndexByte(n.text, '/'); index >= 0 {
		switch n.text[:index] {
		case "/bin", "/usr/bin", "/sbin", "/usr/sbin", "/etc/init.d":
		default:
			a.requireApproval(High, "executable path is outside standard system locations: "+short(n.text), "")
		}
	}
	c := &call{s: s, name: name, args: args, in: in, depth: depth, label: name, subAt: -1}
	switch {
	case wrappers[name] != nil:
		s.wrapper(wrappers[name], c, a)
		return
	case shells[name]:
		s.shell(c, a)
		return
	case isInterpreter(name):
		s.interpreter(c, a)
		return
	}
	r := lookupRule(name)
	if r == nil {
		if strings.Contains(n.text, "/") {
			a.requireApproval(High, "runs a local program or script that cannot be reviewed: "+short(n.text), "Read the script first (cat), then run it")
		} else {
			a.requireApproval(Medium, "unrecognized command "+short(name), "")
		}
		return
	}
	s.apply(r, c, a)
}

func phrase(l Level) string {
	switch l {
	case Medium:
		return "modifies files, configuration or state"
	case High:
		return "destructive, privileged or hard to undo"
	case Critical:
		return "can destroy data or lock you out"
	}
	return "read-only"
}

func (s *state) apply(r *rule, c *call, a *acc) {
	lvl := r.level
	c.label = c.name
	c.subAt = -1
	if len(r.subs) > 0 || len(r.nested) > 0 {
		if at := findSub(c.args, r.optArg, r.subIdx); at >= 0 {
			c.subAt = at
			sub := c.args[at].text
			c.label = c.name + " " + short(sub)
			if l, ok := r.subs[sub]; ok {
				lvl = l
			} else if r.hasDef {
				lvl = r.def
				if r.nested[sub] == nil {
					a.recordApproval("unrecognized subcommand " + c.label)
				}
			}
			if nr := r.nested[sub]; nr != nil {
				nc := *c
				nc.name = c.label
				nc.args = c.args[at+1:]
				s.apply(nr, &nc, a)
				return
			}
		}
	}
	for _, f := range r.flags {
		if hasFlag(c.args, f.short, f.long...) {
			a.add(f.level, c.label+": "+f.why, r.safer)
			if f.level > lvl {
				lvl = f.level
			}
		}
	}
	a.add(lvl, c.label+": "+phrase(lvl), r.safer)
	if r.check != nil {
		r.check(c, a)
	}
}

type wrapSpec struct {
	level  Level
	optArg map[string]bool
	pos    int
	env    bool
	script bool
	why    string
	safer  string
}

func (s *state) wrapper(w *wrapSpec, c *call, a *acc) {
	if c.name == "command" && hasFlag(c.args, "vV") {
		return
	}
	a.add(w.level, c.name+": "+w.why, w.safer)
	args := c.args
	posLeft := w.pos
	i := 0
	for i < len(args) {
		t := args[i].text
		if t == "--" {
			i++
			break
		}
		if len(t) > 1 && t[0] == '-' {
			if w.optArg[t] {
				i++
			}
			i++
			continue
		}
		if w.env && args[i].isAssign() {
			assignment(args[i], a)
			i++
			continue
		}
		if posLeft > 0 {
			posLeft--
			i++
			continue
		}
		break
	}
	if i > len(args) {
		i = len(args)
	}
	inner := args[i:]
	if len(inner) == 0 {
		return
	}
	if w.script {
		var parts []string
		for _, x := range inner {
			if x.dyn() {
				a.requireApproval(High, c.name+" runs a command line built from variables", "")
				return
			}
			parts = append(parts, x.text)
		}
		a.merge(s.analyze(strings.Join(parts, " "), c.depth+1))
		return
	}
	in := c.in
	if c.name == "xargs" {
		in = stdin{}
	}
	s.words(inner, in, c.depth+1, a)
}

func (s *state) shell(c *call, a *acc) {
	args := c.args
	hasC := false
	i := 0
	for i < len(args) {
		t := args[i].text
		if t == "--" {
			i++
			break
		}
		if len(t) > 1 && (t[0] == '-' || t[0] == '+') {
			if t[0] == '-' && t[1] != '-' && strings.IndexByte(t, 'c') >= 0 {
				hasC = true
			}
			if t == "-o" || t == "+o" || t == "-O" || t == "+O" || t == "--rcfile" || t == "--init-file" {
				i++
			}
			i++
			continue
		}
		break
	}
	if i > len(args) {
		i = len(args)
	}
	rest := args[i:]
	if hasC {
		if len(rest) == 0 {
			a.requireApproval(High, c.name+" -c without a script", "")
			return
		}
		sc := rest[0]
		if sc.dyn() {
			a.requireApproval(High, c.name+" -c runs a script built from variables or substitutions", "Write the script out literally")
			return
		}
		a.merge(s.analyze(sc.text, c.depth+1))
		return
	}
	if len(rest) == 0 && len(args) > 0 {
		all := true
		for _, x := range args {
			if x.text != "--version" && x.text != "--help" && x.text != "-version" {
				all = false
			}
		}
		if all {
			return
		}
	}
	switch c.in.kind {
	case inPipe:
		a.requireApproval(High, "pipes data into a shell, which executes it (remote code execution risk)", "Save the text to a file, read it, then run it")
	case inHere:
		a.requireApproval(High, "a here-document or here-string feeds a shell", "Review the text, then run its commands directly")
	case inFile:
		a.requireApproval(High, "a shell reads commands from a file or stdin", "")
	default:
		if len(rest) > 0 {
			a.requireApproval(High, "runs a shell script that cannot be reviewed", "Read the script first (cat), then run it")
		} else {
			a.requireApproval(High, "starts a shell", "")
		}
	}
	if c.in.text != "" {
		a.merge(s.analyze(c.in.text, c.depth+1))
	}
}

func (s *state) interpreter(c *call, a *acc) {
	if len(c.args) == 1 {
		switch c.args[0].text {
		case "--version", "-V", "-v", "--help", "-h", "-version":
			return
		}
	}
	if c.in.kind == inPipe {
		a.requireApproval(High, "pipes data into "+c.name+", which executes it", "Save the text to a file, read it, then run it")
		return
	}
	a.requireApproval(High, c.name+" runs code that cannot be reviewed", "Read the script first (cat), then run it")
}

// hasFlag reports whether args contain one of the short option letters in
// short (alone or clustered) or one of the long options. Scanning stops at "--".
func hasFlag(args []word, short string, long ...string) bool {
	for _, w := range args {
		t := w.text
		if t == "--" {
			return false
		}
		if len(t) < 2 || t[0] != '-' {
			continue
		}
		if t[1] == '-' {
			name := t
			if i := strings.IndexByte(t, '='); i > 0 {
				name = t[:i]
			}
			for _, l := range long {
				if name == l {
					return true
				}
			}
			continue
		}
		for j := 1; j < len(t); j++ {
			if strings.IndexByte(short, t[j]) >= 0 {
				return true
			}
		}
	}
	return false
}

// positional returns the arguments that are not options. optArg lists
// options that take a separate value.
func positional(args []word, optArg map[string]bool) []word {
	var out []word
	for i := 0; i < len(args); i++ {
		t := args[i].text
		if t == "--" {
			out = append(out, args[i+1:]...)
			break
		}
		if len(t) > 1 && t[0] == '-' {
			if optArg[t] {
				i++
			}
			continue
		}
		out = append(out, args[i])
	}
	return out
}

// findSub returns the index in args of the idx-th positional argument, or -1.
func findSub(args []word, optArg map[string]bool, idx int) int {
	n := 0
	for i := 0; i < len(args); i++ {
		t := args[i].text
		if t == "--" {
			if i+1+(idx-n) < len(args) {
				return i + 1 + (idx - n)
			}
			return -1
		}
		if len(t) > 1 && t[0] == '-' {
			if optArg[t] {
				i++
			}
			continue
		}
		if n == idx {
			return i
		}
		n++
	}
	return -1
}

func joinText(ws []word) string {
	parts := make([]string, len(ws))
	for i, w := range ws {
		parts[i] = w.text
	}
	return strings.Join(parts, " ")
}

func anyDyn(ws []word) bool {
	for _, w := range ws {
		if w.dyn() {
			return true
		}
	}
	return false
}
