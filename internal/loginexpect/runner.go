// Package loginexpect runs ordered prompt/response rules against terminal
// output. A host saves a list of Expect/Send rules; once its shell is open the
// runner watches the output, sends each response in turn, and gives up at the
// rule's timeout so the terminal goes back to the user.
//
// The runner keeps no window and no clock of its own: the caller feeds it the
// output it received and the current time, and the runner reports what it needs
// next. That keeps it testable without a network and lets the window decide how
// a sensitive response is asked for. Output is never consumed from the terminal;
// the runner keeps only its own copy of recent bytes.
package loginexpect

import (
	"bytes"
	"errors"
	"time"
)

// maxBuffer bounds the bytes the runner keeps while waiting for a prompt that
// has not arrived yet. A longer Expect keeps at least enough to match it across
// two reads.
const maxBuffer = 256 << 10

// Errors a caller acts on; test with errors.Is.
var (
	// ErrTimeout means a rule's prompt did not appear in time.
	ErrTimeout = errors.New("login expect: prompt timed out")
	// ErrWrite means the shell refused the rule's response.
	ErrWrite = errors.New("login expect: shell rejected input")
	// ErrCanceled means the run was stopped before it finished.
	ErrCanceled = errors.New("login expect: cancelled")
)

// Writer sends a response to the shell. sensitive is true for a response the
// caller asked for at runtime; such a response must not be recorded or logged.
type Writer func(payload []byte, sensitive bool) bool

// EventKind is what the runner needs next.
type EventKind uint8

const (
	// EventWait means the runner is waiting for more output, a timeout, or the
	// answer to a rule that needs no output.
	EventWait EventKind = iota
	// EventSecret means the current rule needs a response the user must type.
	EventSecret
	// EventDone means every rule has run.
	EventDone
	// EventFailed means the run stopped: a timeout, a refused write or a cancel.
	EventFailed
)

// Event is one outcome of Advance or ProvideSecret.
type Event struct {
	Kind EventKind
	// Step is the rule the event concerns; -1 when the run is done.
	Step int
	// Prompt is the text a sensitive rule waited for, for the dialog caption.
	Prompt string
	// Err is why the run failed, for EventFailed.
	Err error
}

// Runner is one shell's progress through its host's rules. It is not safe for
// concurrent use: a window drives it from its own thread.
type Runner struct {
	steps []Step
	index int
	// buffer is the unconsumed tail of the output seen so far.
	buffer   []byte
	deadline time.Time
	awaiting bool
	// matched is true once the current rule's Expect has been consumed; the
	// rule then only waits out its Delay before sending. matchedAt is when that
	// happened, so the delay is measured from the prompt, not from a reply the
	// user typed later.
	matched   bool
	matchedAt time.Time
	// delayDeadline is when a matched rule may send, or the zero time when it
	// has no delay left to wait out.
	delayDeadline time.Time
	// commandPrefixSent is true once a CommandMode rule's leading ":" has been
	// written; commandDeadline is when its reply may then be sent. Both belong
	// to the current rule and are cleared when it advances.
	commandPrefixSent bool
	commandDeadline   time.Time
	// staged is a sensitive answer held until the delay elapses; stagedValue is
	// used once and cleared as soon as the rule advances.
	staged      bool
	stagedValue string
	// prompt is the text of the sensitive rule now waiting for its answer.
	prompt   string
	finished bool
	err      error
}

// New builds a runner for steps. It is a convenience for a bare list; hosts use
// NewConfig so disabled configurations run nothing.
func New(steps []Step) *Runner {
	return NewConfig(Config{Enabled: true, Steps: steps})
}

// NewConfig builds a runner for cfg. The rules are decoded and normalized here,
// so callers may pass the saved form directly.
func NewConfig(cfg Config) *Runner {
	cfg = Normalize(cfg)
	steps := make([]Step, len(cfg.Steps))
	for index, step := range cfg.Steps {
		step.Expect = DecodeText(step.Expect)
		step.Send = DecodeText(step.Send)
		steps[index] = step
	}
	return &Runner{steps: steps}
}

// Advance is the simple entry point that predates the sensitive prompt: it
// feeds output and runs ordinary rules, returning nil while the runner waits or
// is done. A rule that needs a runtime answer cannot be served through it, so it
// reports ErrWrite; callers that support the prompt use Pump and ProvideSecret.
func (r *Runner) Advance(now time.Time, output []byte, write func([]byte) bool) error {
	r.Feed(output)
	for {
		event := r.Pump(now, func(payload []byte, sensitive bool) bool {
			if sensitive {
				return false
			}
			return write != nil && write(payload)
		})
		switch event.Kind {
		case EventWait, EventDone:
			return nil
		case EventSecret:
			return ErrWrite
		default:
			if event.Err != nil {
				return event.Err
			}
			return ErrWrite
		}
	}
}

// Active reports whether the runner has anything to do.
func (r *Runner) Active() bool { return r != nil && len(r.steps) > 0 }

// Feed hands newly received terminal output to the runner. It appends to the
// runner's own buffer; the caller still shows every byte on the screen.
func (r *Runner) Feed(output []byte) {
	if r == nil || len(output) == 0 || r.finished || r.err != nil {
		return
	}
	r.buffer = append(r.buffer, output...)
	if len(r.buffer) > maxBuffer {
		keep := maxBuffer
		if want := r.expectLen() - 1; want > keep {
			keep = want
		}
		if len(r.buffer) > keep {
			r.buffer = append(r.buffer[:0], r.buffer[len(r.buffer)-keep:]...)
		}
	}
}

// Pump runs every rule that can run now: rules whose prompt is already in the
// buffer, and rules that need no prompt. It calls write for each ordinary
// response. A sensitive rule stops the loop and returns EventSecret; the caller
// answers with ProvideSecret.
//
// A rule with a Delay pauses after its prompt matches and before it writes. Pump
// reports EventWait for that pause; the caller asks DelayDeadline when to call
// back. The pause is measured from the match, so a sensitive rule's answer is
// sent as soon as it is typed once the delay has already passed.
//
// A CommandMode rule writes a bare ":" first, then pauses (its Delay, or
// CommandModePause when that is zero) and asks the caller to call back at
// CommandDeadline before writing its reply. That lets a menu shell switch into
// its command line, so a reply containing a colon is no longer cut at that
// colon.
func (r *Runner) Pump(now time.Time, write Writer) Event {
	if r == nil {
		return Event{Kind: EventDone, Step: -1}
	}
	if r.err != nil {
		return Event{Kind: EventFailed, Step: r.index, Err: r.err}
	}
	if r.finished {
		return Event{Kind: EventDone, Step: -1}
	}
	if r.awaiting {
		return Event{Kind: EventSecret, Step: r.index, Prompt: r.prompt}
	}
	for {
		if r.index >= len(r.steps) {
			r.finished = true
			r.buffer = nil
			return Event{Kind: EventDone, Step: -1}
		}
		step := r.steps[r.index]
		if !r.matched {
			if step.Expect != "" {
				if r.deadline.IsZero() {
					r.deadline = now.Add(step.Timeout)
				}
				position := bytes.Index(r.buffer, []byte(step.Expect))
				if position < 0 {
					if !now.Before(r.deadline) {
						return r.fail(ErrTimeout)
					}
					r.trim(len(step.Expect) - 1)
					return Event{Kind: EventWait, Step: r.index}
				}
				r.buffer = r.buffer[position+len(step.Expect):]
			}
			r.matched = true
			r.matchedAt = now
			// The prompt is in hand: its timeout no longer applies, only the
			// optional delay before the reply.
			r.deadline = time.Time{}
		}
		if step.Sensitive && !r.staged {
			r.awaiting = true
			r.prompt = step.Expect
			return Event{Kind: EventSecret, Step: r.index, Prompt: step.Expect}
		}
		// A CommandMode rule types a bare ":" first, then pauses, so a menu
		// shell can switch into its command line before the reply goes in. Its
		// Delay is that pause (zero uses CommandModePause), and the reply
		// follows once the pause has passed.
		if step.CommandMode {
			if !r.commandPrefixSent {
				if write == nil || !write([]byte(":"), false) {
					return r.fail(ErrWrite)
				}
				r.commandPrefixSent = true
				pause := step.Delay
				if pause <= 0 {
					pause = CommandModePause
				}
				r.commandDeadline = now.Add(pause)
				return Event{Kind: EventWait, Step: r.index}
			}
			if now.Before(r.commandDeadline) {
				return Event{Kind: EventWait, Step: r.index}
			}
			r.commandDeadline = time.Time{}
		} else if step.Delay > 0 {
			due := r.matchedAt.Add(step.Delay)
			if now.Before(due) {
				r.delayDeadline = due
				return Event{Kind: EventWait, Step: r.index}
			}
		}
		r.delayDeadline = time.Time{}
		value, sensitive := step.Send, false
		if step.Sensitive {
			value, sensitive = r.stagedValue, true
		}
		if !r.send(value, sensitive, write) {
			return r.fail(ErrWrite)
		}
		r.advance()
	}
}

// ProvideSecret answers the sensitive rule that returned EventSecret and keeps
// running. The answer is sent marked sensitive so the shell records it but the
// window can keep it out of history and logs.
func (r *Runner) ProvideSecret(value string, now time.Time, write Writer) Event {
	if r == nil {
		return Event{Kind: EventDone, Step: -1}
	}
	if r.err != nil {
		return Event{Kind: EventFailed, Step: r.index, Err: r.err}
	}
	if !r.awaiting {
		return r.Pump(now, write)
	}
	r.awaiting = false
	r.prompt = ""
	// Stage the answer and let Pump apply the rule's delay and write it. The
	// value lives here only until the rule advances or the run is cancelled.
	r.staged = true
	r.stagedValue = value
	return r.Pump(now, write)
}

// advance moves to the next rule and clears everything that belonged to the one
// just finished, including any staged sensitive answer.
func (r *Runner) advance() {
	r.index++
	r.matched = false
	r.matchedAt = time.Time{}
	r.deadline = time.Time{}
	r.delayDeadline = time.Time{}
	r.commandPrefixSent = false
	r.commandDeadline = time.Time{}
	r.staged = false
	r.stagedValue = ""
}

// send writes one response, appending the rule's Enter when asked.
func (r *Runner) send(value string, sensitive bool, write Writer) bool {
	step := r.steps[r.index]
	payload := []byte(value)
	if step.AppendEnter {
		payload = append(payload, '\r')
	}
	if len(payload) == 0 {
		return true
	}
	return write != nil && write(payload, sensitive)
}

// fail records a terminal failure and returns its event. It clears everything
// the run was holding, so a staged sensitive answer, an open question, buffered
// output or a pending timer never outlives the run. The rule index is kept so
// the event and Failed still name the rule that failed.
func (r *Runner) fail(err error) Event {
	r.stop(err)
	return Event{Kind: EventFailed, Step: r.index, Err: err}
}

// stop ends the run with err and forgets all per-rule state. Every terminal
// path goes through it: a timeout, a refused write, a cancel, or a disconnect.
func (r *Runner) stop(err error) {
	r.err = err
	r.finished = false
	r.awaiting = false
	r.prompt = ""
	r.buffer = nil
	r.deadline = time.Time{}
	r.delayDeadline = time.Time{}
	r.commandPrefixSent = false
	r.commandDeadline = time.Time{}
	r.matched = false
	r.matchedAt = time.Time{}
	r.staged = false
	r.stagedValue = ""
}

func (r *Runner) expectLen() int {
	if r.index >= len(r.steps) {
		return 0
	}
	return len(r.steps[r.index].Expect)
}

// trim keeps the tail of the buffer that could still begin a match.
func (r *Runner) trim(keep int) {
	if keep < 0 {
		keep = 0
	}
	if len(r.buffer) <= keep {
		return
	}
	r.buffer = append(r.buffer[:0], r.buffer[len(r.buffer)-keep:]...)
}

// Cancel stops the runner: a cancelled run is reported as failed but sends
// nothing more. It is what closing a tab, a disconnect or a user refusal does.
func (r *Runner) Cancel() {
	if r == nil || r.finished || r.err != nil {
		return
	}
	r.stop(ErrCanceled)
}

// Done reports whether every rule has run.
func (r *Runner) Done() bool { return r == nil || r.finished || r.index >= len(r.steps) }

// Failed reports the error that stopped the run, or nil.
func (r *Runner) Failed() error {
	if r == nil {
		return nil
	}
	return r.err
}

// Awaiting reports whether a sensitive rule waits for the user's answer.
func (r *Runner) Awaiting() bool { return r != nil && r.awaiting }

// Prompt is the text of the sensitive rule now waiting, or empty.
func (r *Runner) Prompt() string { return r.prompt }

// Deadline is when the current wait times out, or the zero time when it has no
// deadline (a rule that sends without waiting, a rule paused before its reply,
// or a done run).
func (r *Runner) Deadline() time.Time {
	if r == nil || r.awaiting || r.finished || r.err != nil {
		return time.Time{}
	}
	return r.deadline
}

// DelayDeadline is when a matched rule's delay ends and its reply may be sent,
// or the zero time when no rule is waiting out a delay. It is separate from
// Deadline so the caller can wake for whichever comes first.
func (r *Runner) DelayDeadline() time.Time {
	if r == nil || r.awaiting || r.finished || r.err != nil {
		return time.Time{}
	}
	return r.delayDeadline
}

// CommandDeadline is when a CommandMode rule may send its reply after the
// leading ":", or the zero time when no rule is waiting that pause out. It is
// separate from the other deadlines so the caller can wake for whichever comes
// first.
func (r *Runner) CommandDeadline() time.Time {
	if r == nil || r.awaiting || r.finished || r.err != nil {
		return time.Time{}
	}
	return r.commandDeadline
}

// Index is the rule the runner is on, for messages.
func (r *Runner) Index() int { return r.index }
