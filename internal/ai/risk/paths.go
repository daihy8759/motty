package risk

import (
	"path"
	"strings"
	"unicode/utf8"
)

func set(s string) map[string]bool {
	m := map[string]bool{}
	for _, f := range strings.Fields(s) {
		m[f] = true
	}
	return m
}

func baseName(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// short makes untrusted text safe and compact for a reason string.
func short(s string) string {
	if len(s) > 40 {
		s = s[:40]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
		s += "..."
	}
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return '?'
		}
		return r
	}, s)
}

func pureGlobSegment(seg string) bool {
	if seg == "" || !strings.Contains(seg, "*") {
		return false
	}
	for i := 0; i < len(seg); i++ {
		if seg[i] != '*' && seg[i] != '.' {
			return false
		}
	}
	return true
}

// normPath lexically cleans a path. $HOME becomes ~. glob reports that the last
// segment was a bare wildcard such as "*" or ".*", which is removed.
func normPath(t string) (string, bool) {
	switch {
	case t == "$HOME" || strings.HasPrefix(t, "$HOME/"):
		t = "~" + t[5:]
	case t == "${HOME}" || strings.HasPrefix(t, "${HOME}/"):
		t = "~" + t[7:]
	}
	glob := false
	if i := strings.LastIndexByte(t, '/'); i >= 0 || t != "" {
		seg := t[i+1:]
		if pureGlobSegment(seg) {
			glob = true
			t = t[:i+1]
			if t == "" {
				t = "."
			}
		}
	}
	if strings.HasPrefix(t, "~") {
		prefix, rest := t, ""
		if i := strings.IndexByte(t, '/'); i >= 0 {
			prefix, rest = t[:i], t[i:]
		}
		c := path.Clean("/" + rest)
		if c == "/" {
			return prefix, glob
		}
		return prefix + c, glob
	}
	return path.Clean(t), glob
}

var (
	deep2 = set("usr etc bin sbin lib lib32 lib64 libx32 boot dev sys proc")
	deep1 = set("var home root opt srv mnt media snap run lost+found cdrom")
)

// isSystemRoot reports whether the cleaned absolute path is "/" or a
// top-level system directory (or a direct child of the important ones).
func isSystemRoot(p string) bool {
	if p == "/" {
		return true
	}
	if !strings.HasPrefix(p, "/") {
		return false
	}
	segs := strings.Split(p[1:], "/")
	if deep2[segs[0]] && len(segs) <= 2 {
		return true
	}
	return deep1[segs[0]] && len(segs) == 1
}

var systemTrees = set("etc boot usr bin sbin lib lib32 lib64 libx32 sys proc")

func inSystemTree(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	seg := p[1:]
	if i := strings.IndexByte(seg, '/'); i >= 0 {
		seg = seg[:i]
	}
	return systemTrees[seg]
}

var benignDevs = set("null zero full random urandom tty stdin stdout stderr console ptmx")

func benignDev(p string) bool {
	if !strings.HasPrefix(p, "/dev/") {
		return false
	}
	r := p[5:]
	if benignDevs[r] {
		return true
	}
	for _, pre := range []string{"fd/", "pts/", "shm/", "tcp/", "udp/", "tty"} {
		if strings.HasPrefix(r, pre) {
			return true
		}
	}
	return false
}

var blockPrefixes = []string{"sd", "hd", "vd", "xvd", "nvme", "mmcblk", "loop", "md", "dm-", "sr", "disk", "rdisk", "mapper/", "mem", "kmem", "port", "dasd", "ram", "nbd", "zram", "rbd", "vg", "mtd", "block/", "fb"}

func isBlockDev(p string) bool {
	if !strings.HasPrefix(p, "/dev/") {
		return false
	}
	r := p[5:]
	for _, pre := range blockPrefixes {
		if strings.HasPrefix(r, pre) {
			return true
		}
	}
	return false
}

var sensNames = set("authorized_keys authorized_keys2 sshd_config ssh_config id_rsa id_dsa id_ecdsa id_ed25519 id_ecdsa_sk id_ed25519_sk shadow gshadow passwd group sudoers fstab crypttab")

// sensitive reports files whose loss or overwrite can lock the user out.
func sensitive(p string) bool {
	b := path.Base(p)
	if sensNames[b] {
		return true
	}
	if strings.HasPrefix(b, "ssh_host_") && strings.HasSuffix(b, "_key") {
		return true
	}
	if b == ".ssh" || b == "sudoers.d" || p == "/etc/ssh" || strings.HasPrefix(p, "/etc/ssh/") {
		return true
	}
	return false
}

var credBases = set("id_rsa id_dsa id_ecdsa id_ed25519 id_ecdsa_sk id_ed25519_sk shadow gshadow .netrc .pgpass .git-credentials")

// credWord reports text that names private key or credential material.
func credWord(t string) bool {
	b := baseName(t)
	if credBases[b] {
		return true
	}
	if b == "credentials" && strings.Contains(t, ".aws") {
		return true
	}
	if strings.HasPrefix(b, "ssh_host_") && strings.HasSuffix(b, "_key") {
		return true
	}
	return strings.HasSuffix(b, ".key") && !strings.HasSuffix(b, "_pub.key")
}

func isDotDots(p string) bool {
	for _, s := range strings.Split(p, "/") {
		if s != ".." {
			return false
		}
	}
	return p != ""
}

// pathDanger describes why operating on p is catastrophic, or "".
// rel enables the checks for the current directory.
func pathDanger(p string, glob, recursive, rel bool) string {
	switch {
	case p == "/":
		return "targets the filesystem root"
	case strings.HasPrefix(p, "/"):
		if (recursive || glob) && isSystemRoot(p) {
			return "targets a top-level system directory"
		}
	case strings.HasPrefix(p, "~"):
		if !strings.Contains(p, "/") && (recursive || glob) {
			return "targets the home directory"
		}
	case rel && recursive && (p == "." || p == ".." || isDotDots(p)):
		return "targets the current or parent directory"
	}
	return ""
}

func emptyTail(tail string) bool {
	switch tail {
	case "/", "/*", "*", "/.*", "/.", "/**":
		return true
	}
	return false
}

// delDanger describes why deleting or recursively changing w is catastrophic.
func delDanger(w word, recursive, rel bool) string {
	if recursive && w.hasVar && !w.guarded && (w.unqVar || emptyTail(w.tail)) {
		return "target uses a variable that may be empty"
	}
	for _, alt := range expandBraces(w.text, 32, 0) {
		p, glob := normPath(alt)
		if r := pathDanger(p, glob, recursive, rel); r != "" {
			return r
		}
	}
	return ""
}

func expandBraces(s string, limit, depth int) []string {
	i := strings.IndexByte(s, '{')
	if i < 0 || depth > 6 {
		return []string{s}
	}
	d, end := 0, -1
	var cuts []int
scan:
	for j := i; j < len(s); j++ {
		switch s[j] {
		case '{':
			d++
		case '}':
			d--
			if d == 0 {
				end = j
				break scan
			}
		case ',':
			if d == 1 {
				cuts = append(cuts, j)
			}
		}
	}
	if end < 0 || len(cuts) == 0 {
		return []string{s}
	}
	pre, post := s[:i], s[end+1:]
	var out []string
	start := i + 1
	for _, c := range append(cuts, end) {
		for _, r := range expandBraces(pre+s[start:c]+post, limit, depth+1) {
			out = append(out, r)
			if len(out) >= limit {
				return out
			}
		}
		start = c + 1
	}
	return out
}
