package workbench

import (
	"errors"
	"fmt"
	"time"

	"github.com/vivaui/viva/text"
	"github.com/vivaui/viva/ui"
	"motty/internal/loginexpect"
)

// Login Expect/Send at runtime. The host saves ordered rules; once its shell is
// open the runner watches the output and sends each response in turn. Everything
// here runs on the window's thread, as the terminal does, so no lock is needed.
// The output is still drawn in full: the runner keeps its own copy and never
// consumes the bytes the screen shows.

// loginExpectEpoch turns the window's monotonic duration into the time.Time the
// runner's deadlines use, so timeouts follow the same clock as the rest of the
// window (and a fake clock in tests).
var loginExpectEpoch = time.Unix(0, 0)

func (state *State) loginExpectNow() time.Time { return loginExpectEpoch.Add(state.now()) }

// loginExpectAsk is a sensitive rule waiting for the user's answer. It is kept
// on its session, not in one global slot: two shells can ask at once, and the
// one whose dialog is already on screen must keep its editor untouched.
type loginExpectAsk struct {
	prompt string
	editor text.Editor
}

// startLoginExpect begins the host's rules for a shell that has just opened.
// A new shell always starts from the first rule, so a reconnect repeats them.
func (state *State) startLoginExpect(session *Session) {
	state.stopLoginExpect(session)
	if session == nil || session.term == nil {
		return
	}
	cfg := session.host.LoginExpect
	if cfg == nil || !cfg.Active() {
		return
	}
	session.loginExpect = loginexpect.NewConfig(*cfg)
	state.driveLoginExpect(session, state.loginExpectNow())
}

// stopLoginExpect forgets a shell's run: closing, a disconnect, a cancel and a
// reconnect all drop it, and nothing it had asked for stays on screen.
func (state *State) stopLoginExpect(session *Session) {
	if session == nil {
		return
	}
	session.loginExpectAsk = nil
	if session.loginExpect != nil {
		session.loginExpect.Cancel()
		session.loginExpect = nil
	}
	// If this session's prompt was on screen, let the next waiting shell show
	// its own instead of leaving the window stuck behind a closed dialog.
	if state.modal == modalLoginExpectSecret && state.modalSession == session.ID {
		state.modal = modalNone
		state.modalSession = 0
		state.showNextPrompt()
	}
}

// loginExpectWriter sends a rule's response to the shell. A sensitive response
// goes through sendSecret, which records only enough to keep its echo out of a
// recording; an ordinary one through sendLoginReply. Both write the saved
// bytes exactly: a colon in a reply is data and never a separator.
func (state *State) loginExpectWriter(session *Session) loginexpect.Writer {
	return func(payload []byte, sensitive bool) bool {
		t := session.term
		if t == nil || t.shell == nil {
			return false
		}
		if sensitive {
			return t.sendSecret(payload)
		}
		return t.sendLoginReply(payload)
	}
}

// driveLoginExpect runs every rule that can run now and leaves the runner
// waiting, asking, done or failed.
func (state *State) driveLoginExpect(session *Session, now time.Time) {
	runner := session.loginExpect
	if runner == nil || runner.Awaiting() {
		return
	}
	writer := state.loginExpectWriter(session)
	for {
		event := runner.Pump(now, writer)
		switch event.Kind {
		case loginexpect.EventWait:
			return
		case loginexpect.EventDone:
			session.loginExpect = nil
			return
		case loginexpect.EventSecret:
			state.askLoginExpect(session, event.Prompt, event.Step)
			return
		case loginexpect.EventFailed:
			state.failLoginExpect(session, event.Err)
			return
		}
	}
}

// handleLoginExpectEvent continues after an answer, which may in turn ask for
// another sensitive value or finish.
func (state *State) handleLoginExpectEvent(session *Session, event loginexpect.Event) {
	runner := session.loginExpect
	writer := state.loginExpectWriter(session)
	for runner != nil {
		switch event.Kind {
		case loginexpect.EventWait:
			return
		case loginexpect.EventDone:
			session.loginExpect = nil
			return
		case loginexpect.EventSecret:
			state.askLoginExpect(session, event.Prompt, event.Step)
			return
		case loginexpect.EventFailed:
			state.failLoginExpect(session, event.Err)
			return
		}
		event = runner.Pump(state.loginExpectNow(), writer)
	}
}

func (state *State) askLoginExpect(session *Session, prompt string, step int) {
	if session == nil {
		return
	}
	// A second event for a session that is already asking must not replace the
	// dialog the user may be typing into.
	if session.loginExpectAsk != nil {
		state.showNextPrompt()
		return
	}
	if prompt == "" {
		prompt = fmt.Sprintf(state.messages.LoginExpect.ResponseFmt, step+1)
	}
	session.loginExpectAsk = &loginExpectAsk{prompt: prompt}
	state.showNextPrompt()
}

// loginExpectAskSession is the session whose sensitive prompt is on screen.
func (state *State) loginExpectAskSession() *Session {
	if state.modal != modalLoginExpectSecret {
		return nil
	}
	for index := range state.sessions {
		if state.sessions[index].ID == state.modalSession {
			return &state.sessions[index]
		}
	}
	return nil
}

// nextLoginExpectAsk picks the first shell whose runner is waiting for a
// sensitive answer, in session order. A runner that is waiting always has an
// answer it can show; an ask whose editor was never created gets one here.
func (state *State) nextLoginExpectAsk() *Session {
	for index := range state.sessions {
		session := &state.sessions[index]
		if session.loginExpect == nil || !session.loginExpect.Awaiting() {
			continue
		}
		if session.loginExpectAsk == nil {
			prompt := session.loginExpect.Prompt()
			if prompt == "" {
				prompt = fmt.Sprintf(state.messages.LoginExpect.ResponseFmt, session.loginExpect.Index()+1)
			}
			session.loginExpectAsk = &loginExpectAsk{prompt: prompt}
		}
		return session
	}
	return nil
}

// provideLoginExpectSecret answers the open sensitive prompt and continues the
// run. The value is used once and then forgotten: it is never saved or logged.
func (state *State) provideLoginExpectSecret(session *Session, value string) {
	if session == nil {
		state.showNextPrompt()
		return
	}
	session.loginExpectAsk = nil
	if state.modal == modalLoginExpectSecret && state.modalSession == session.ID {
		state.modal = modalNone
		state.modalSession = 0
	}
	if session.loginExpect == nil {
		state.showNextPrompt()
		return
	}
	event := session.loginExpect.ProvideSecret(value, state.loginExpectNow(), state.loginExpectWriter(session))
	state.handleLoginExpectEvent(session, event)
	state.showNextPrompt()
}

// cancelLoginExpect stops the run and returns the shell to the user: a refusal
// is never a timeout, and later rules do not run.
func (state *State) cancelLoginExpect(session *Session) {
	if session == nil {
		return
	}
	session.loginExpectAsk = nil
	if state.modal == modalLoginExpectSecret && state.modalSession == session.ID {
		state.modal = modalNone
		state.modalSession = 0
	}
	if session.loginExpect != nil {
		session.loginExpect.Cancel()
		session.loginExpect = nil
		if session.term != nil {
			session.term.say(sgrWarn, state.messages.LoginExpect.Cancelled)
		}
	}
	state.showNextPrompt()
}

// failLoginExpect tells the user why the rules stopped and leaves the shell to
// them. The tab stays open and manual typing keeps working.
func (state *State) failLoginExpect(session *Session, err error) {
	session.loginExpectAsk = nil
	session.loginExpect = nil
	message := fmt.Sprintf(state.messages.LoginExpect.FailedFmt, err)
	switch {
	case err == nil:
		return
	case errors.Is(err, loginexpect.ErrTimeout):
		message = state.messages.LoginExpect.Timeout
	case errors.Is(err, loginexpect.ErrWrite):
		message = state.messages.LoginExpect.WriteFailed
	case errors.Is(err, loginexpect.ErrCanceled):
		// A cancel from the user's own refusal already said so.
		return
	}
	if session.term != nil {
		session.term.say(sgrWarn, message)
	}
	state.status = message
}

// feedLoginExpect hands newly received output to the runner and lets it act.
// It is called with the same bytes the screen just received, so nothing is
// swallowed from the terminal.
func (state *State) feedLoginExpect(session *Session, output []byte) {
	if session.loginExpect == nil {
		return
	}
	session.loginExpect.Feed(output)
	state.driveLoginExpect(session, state.loginExpectNow())
}

// requestLoginExpectFrames asks for the frame that notices a rule's timeout. A
// shell with no active rules asks for nothing.
func (state *State) requestLoginExpectFrames(canvas *ui.Canvas) {
	now := state.loginExpectNow()
	for index := range state.sessions {
		session := &state.sessions[index]
		runner := session.loginExpect
		if runner == nil || runner.Awaiting() {
			continue
		}
		deadline := runner.Deadline()
		if delay := runner.DelayDeadline(); !delay.IsZero() && (deadline.IsZero() || delay.Before(deadline)) {
			deadline = delay
		}
		if !deadline.IsZero() {
			wait := deadline.Sub(now)
			if wait < time.Millisecond {
				wait = time.Millisecond
			}
			canvas.RequestFrameIn(wait)
		}
	}
}

// clickLoginExpectSecret handles the sensitive-response dialog. Dismissing it
// cancels the run rather than sending anything.
func (state *State) clickLoginExpectSecret(id ui.ID) {
	session := state.loginExpectAskSession()
	if session == nil || session.loginExpectAsk == nil {
		if state.modal == modalLoginExpectSecret {
			state.modal = modalNone
			state.modalSession = 0
		}
		state.showNextPrompt()
		return
	}
	switch id {
	case hitLoginExpectSubmit:
		value := session.loginExpectAsk.editor.String()
		state.provideLoginExpectSecret(session, value)
	case hitLoginExpectCancel, hitLoginExpectClose, hitLoginExpectDismiss:
		state.cancelLoginExpect(session)
	}
}
