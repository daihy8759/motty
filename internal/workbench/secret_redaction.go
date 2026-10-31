package workbench

import (
	"bytes"
	"sort"
)

// Secret redaction for the terminal recording. A sensitive reply is sent with
// sendSecret, which keeps it out of the recorded input; a remote that echoes it
// would still put the same bytes into the output stream. This redactor removes
// that echo from the bytes handed to the recording while the screen keeps
// showing everything.
//
// The matching is streaming: a reply may arrive split across reads, so a tail
// that could begin a reply is held back until the next read completes or rules
// it out. The hold is bounded by the longest pending reply, and a reply is only
// replaced when it stands as a token of its own (not inside a longer word), so
// ordinary output that merely contains similar text is recorded unchanged.
const (
	secretRedactionMaxSecrets = 8
	secretRedactionMaxLength  = 4096
)

type secretGuard struct {
	value     []byte
	remaining int
}

// secretRedactor is the per-terminal streaming filter. It is touched only on
// the window's thread, with the terminal.
type secretRedactor struct {
	guards  []secretGuard
	pending []byte
	// last is the last byte of the stream seen before pending (or before the
	// next read), used to decide the left boundary of a match that begins a
	// chunk.
	last    byte
	hasLast bool
}

// add registers one sensitive response. The trailing newline a response is sent
// with is not part of the value a prompt echoes, so it is trimmed.
func (r *secretRedactor) add(payload []byte) {
	value := bytes.TrimRight(payload, "\r\n")
	if len(value) == 0 || len(value) > secretRedactionMaxLength {
		return
	}
	for index := range r.guards {
		if bytes.Equal(r.guards[index].value, value) {
			r.guards[index].remaining = 1
			return
		}
	}
	if len(r.guards) >= secretRedactionMaxSecrets {
		copy(r.guards, r.guards[1:])
		r.guards = r.guards[:len(r.guards)-1]
	}
	r.guards = append(r.guards, secretGuard{value: append([]byte(nil), value...), remaining: 1})
	// The longest value first: when one reply is a prefix of another, the longer
	// echo is the one to remove.
	sort.SliceStable(r.guards, func(a, b int) bool { return len(r.guards[a].value) > len(r.guards[b].value) })
}

// redact returns the bytes that may be recorded for this read. It may return
// fewer bytes than were passed, holding a possible partial reply for the next
// read.
func (r *secretRedactor) redact(data []byte) []byte { return r.process(data, false) }

// finish processes at end of stream: a held value that is only a prefix of a
// reply is ordinary output and is emitted; a complete reply at the very end is
// still removed. It clears the state.
func (r *secretRedactor) finish() []byte {
	if len(r.guards) == 0 {
		out := append([]byte(nil), r.pending...)
		r.pending = nil
		if len(out) > 0 {
			r.noteTail(out)
		}
		return out
	}
	out := r.process(nil, true)
	r.reset()
	return out
}

// reset forgets pending replies and held bytes. A stopped recording or a new
// shell must never carry a previous shell's secrets forward.
func (r *secretRedactor) reset() {
	r.guards = nil
	r.pending = nil
	r.last, r.hasLast = 0, false
}

func (r *secretRedactor) process(data []byte, eof bool) []byte {
	if len(r.guards) == 0 {
		if len(r.pending) == 0 {
			r.noteTail(data)
			return data
		}
		out := append([]byte(nil), r.pending...)
		r.pending = nil
		out = append(out, data...)
		r.noteTail(out)
		return out
	}
	var buf []byte
	if len(r.pending) > 0 {
		buf = make([]byte, 0, len(r.pending)+len(data))
		buf = append(buf, r.pending...)
		r.pending = nil
	}
	buf = append(buf, data...)
	out := make([]byte, 0, len(buf))
	for i := 0; i < len(buf); {
		if length, ok := r.match(buf, i, eof); ok {
			i += length
			continue
		}
		if r.holdStart(buf, i, eof) {
			r.pending = append(r.pending[:0], buf[i:]...)
			if i > 0 {
				r.last, r.hasLast = buf[i-1], true
			}
			return out
		}
		out = append(out, buf[i])
		i++
	}
	r.noteTail(buf)
	return out
}

// match reports the length of a reply beginning at i that may be removed, and
// whether there is one.
func (r *secretRedactor) match(buf []byte, i int, eof bool) (int, bool) {
	if !r.boundaryBefore(buf, i) {
		return 0, false
	}
	for index := range r.guards {
		guard := &r.guards[index]
		if guard.remaining <= 0 || len(guard.value) == 0 {
			continue
		}
		length := len(guard.value)
		if i+length > len(buf) || !bytes.Equal(buf[i:i+length], guard.value) {
			continue
		}
		if i+length == len(buf) && !eof {
			// The byte after the candidate decides whether it is a token of its
			// own; hold it until the next read.
			return 0, false
		}
		if i+length < len(buf) && isWordByte(buf[i+length]) {
			continue
		}
		guard.remaining--
		return length, true
	}
	return 0, false
}

// holdStart reports whether buf[i:] could still become a reply with more reads.
func (r *secretRedactor) holdStart(buf []byte, i int, eof bool) bool {
	if eof || !r.boundaryBefore(buf, i) {
		return false
	}
	rest := len(buf) - i
	for index := range r.guards {
		guard := &r.guards[index]
		if guard.remaining <= 0 || len(guard.value) == 0 || rest > len(guard.value) {
			continue
		}
		if bytes.Equal(buf[i:], guard.value[:rest]) {
			return true
		}
	}
	return false
}

func (r *secretRedactor) boundaryBefore(buf []byte, i int) bool {
	if i > 0 {
		return !isWordByte(buf[i-1])
	}
	return !r.hasLast || !isWordByte(r.last)
}

func (r *secretRedactor) noteTail(data []byte) {
	if len(data) == 0 {
		return
	}
	r.last, r.hasLast = data[len(data)-1], true
}

// isWordByte says whether b continues a word. A reply embedded in a word is
// ordinary text that happens to contain the same characters, not an echo.
func isWordByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9', b == '_':
		return true
	}
	return false
}
