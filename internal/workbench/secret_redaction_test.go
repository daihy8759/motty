package workbench

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"motty/internal/loginexpect"
	"motty/internal/sshconn"
)

func joinRecordedOutput(recording *terminalRecording) string {
	var builder strings.Builder
	for _, event := range recording.events {
		if event.direction == terminalRecordingOutput {
			builder.Write(event.data)
		}
	}
	return builder.String()
}

func TestSecretRedactionRemovesChunkedEcho(t *testing.T) {
	var redactor secretRedactor
	redactor.add([]byte("s3cret\r"))
	var recorded []byte
	for _, chunk := range []string{"banner\nlo", "gin: s3", "cr", "et\r\n"} {
		input := []byte(chunk)
		original := string(input)
		recorded = append(recorded, redactor.redact(input)...)
		if string(input) != original {
			t.Fatalf("redaction changed the screen input %q", input)
		}
	}
	recorded = append(recorded, redactor.finish()...)
	if bytes.Contains(recorded, []byte("s3cret")) {
		t.Fatalf("recording leaked the reply: %q", recorded)
	}
	if got, want := string(recorded), "banner\nlogin: \r\n"; got != want {
		t.Fatalf("recorded=%q want=%q", got, want)
	}
}

func TestSecretRedactionKeepsNearbyOrdinaryText(t *testing.T) {
	var redactor secretRedactor
	redactor.add([]byte("pass"))
	recorded := redactor.redact([]byte("password ok and pass here"))
	recorded = append(recorded, redactor.finish()...)
	if got, want := string(recorded), "password ok and  here"; got != want {
		t.Fatalf("recorded=%q want=%q", got, want)
	}
	if !strings.Contains(string(recorded), "password") {
		t.Fatalf("ordinary word was damaged: %q", recorded)
	}

	// The same, with the near word split over two reads.
	var split secretRedactor
	split.add([]byte("pass"))
	var splitRecorded []byte
	splitRecorded = append(splitRecorded, split.redact([]byte("pas"))...)
	splitRecorded = append(splitRecorded, split.redact([]byte("sword"))...)
	splitRecorded = append(splitRecorded, split.finish()...)
	if got := string(splitRecorded); got != "password" {
		t.Fatalf("split ordinary word=%q", got)
	}
}

func TestSecretRedactionSettlesDisconnectTail(t *testing.T) {
	// A complete reply held at the very end must still be removed when the
	// stream ends.
	var complete secretRedactor
	complete.add([]byte("s3cret"))
	recorded := complete.redact([]byte("before s3cret"))
	recorded = append(recorded, complete.finish()...)
	if strings.Contains(string(recorded), "s3cret") {
		t.Fatalf("complete trailing reply leaked: %q", recorded)
	}
	if got := string(recorded); got != "before " {
		t.Fatalf("recorded=%q", got)
	}

	// An incomplete prefix is ordinary output and is kept.
	var partial secretRedactor
	partial.add([]byte("s3cret"))
	recorded = partial.redact([]byte("before s3cr"))
	recorded = append(recorded, partial.finish()...)
	if got := string(recorded); got != "before s3cr" {
		t.Fatalf("partial tail=%q", got)
	}
}

func TestTerminalRecordingOmitsSensitiveEcho(t *testing.T) {
	term := newTerminalWithScrollback(80, 24, 100)
	shell := &fakeShell{done: make(chan struct{})}
	term.shell = shell
	term.recording.start(0)
	if !term.sendSecret([]byte("s3cret\r")) {
		t.Fatal("sensitive write was refused")
	}
	term.recording.append(0, terminalRecordingOutput, []byte("login: s3"))
	term.recording.append(0, terminalRecordingOutput, []byte("cret\r\n"))
	term.recording.finishSecrets(0)
	recorded := joinRecordedOutput(&term.recording)
	if strings.Contains(recorded, "s3cret") {
		t.Fatalf("recording leaked the echo: %q", recorded)
	}
	if recorded != "login: \r\n" {
		t.Fatalf("recorded=%q", recorded)
	}
	// The shell still received exactly what was written.
	if got := string(shell.input); got != "s3cret\r" {
		t.Fatalf("shell input=%q", got)
	}
}

func TestTerminalRecordingSettlesTailWhenDisconnected(t *testing.T) {
	term := newTerminalWithScrollback(80, 24, 100)
	shell := &fakeShell{done: make(chan struct{})}
	term.shell = shell
	term.recording.start(0)
	term.sendSecret([]byte("s3cret\r"))
	term.recording.append(0, terminalRecordingOutput, []byte("before s3cret"))
	// What closeDisconnectedShell does for output that is already drained.
	term.recording.finishSecrets(time.Second)
	recorded := joinRecordedOutput(&term.recording)
	if strings.Contains(recorded, "s3cret") {
		t.Fatalf("disconnect tail leaked: %q", recorded)
	}
	if recorded != "before " {
		t.Fatalf("recorded=%q", recorded)
	}
}

func TestStoppingRecordingClearsPendingSecrets(t *testing.T) {
	term := newTerminalWithScrollback(80, 24, 100)
	shell := &fakeShell{done: make(chan struct{})}
	term.shell = shell
	term.recording.start(0)
	term.sendSecret([]byte("s3cret\r"))
	term.recording.append(0, terminalRecordingOutput, []byte("before s3"))
	term.recording.finishSecrets(0)
	term.recording.stop()
	term.recording.resetSecrets()
	if len(term.recording.secret.guards) != 0 || len(term.recording.secret.pending) != 0 {
		t.Fatal("stopping left redaction state behind")
	}
	// A later recording is not filtered by an old reply.
	term.recording.start(time.Second)
	term.recording.append(time.Second, terminalRecordingOutput, []byte("s3cret is ordinary now"))
	recorded := joinRecordedOutput(&term.recording)
	if !strings.Contains(recorded, "s3cret is ordinary now") {
		t.Fatalf("new recording was redacted by an old secret: %q", recorded)
	}
}

func loginExpectRecordingSession(t *testing.T, now *time.Duration) (*State, *fakeShell, *Session) {
	t.Helper()
	world, options := newWorld(t)
	options.Invalidate = func() {}
	options.Now = func() time.Duration { return *now }
	state := newTestState(t, options)
	state.hosts[0].LoginExpect = &loginexpect.Config{Enabled: true, Steps: []loginexpect.Step{
		{Expect: "Password: ", Sensitive: true, AppendEnter: true, Timeout: time.Second},
	}}
	fake := connect(t, state, world)
	fake.set(func(status *sshconn.Status) { status.Phase = sshconn.PhaseConnected })
	state.Wake()
	shell := fake.shell(t)
	session := &state.sessions[0]
	state.toggleTerminalRecording(session)
	return state, shell, session
}

func submitEchoedLoginSecret(t *testing.T, state *State, shell *fakeShell) {
	t.Helper()
	shell.say("Password: ")
	state.Wake()
	if state.modal != modalLoginExpectSecret {
		t.Fatalf("sensitive prompt did not open: modal=%v", state.modal)
	}
	askSession := state.loginExpectAskSession()
	if askSession == nil || askSession.loginExpectAsk == nil {
		t.Fatalf("no sensitive prompt is on screen")
	}
	askSession.loginExpectAsk.editor.Insert("s3cret")
	state.clickLoginExpectSecret(hitLoginExpectSubmit)
}

func TestTerminalRecordingOmitsEchoedSensitiveLoginReply(t *testing.T) {
	now := time.Duration(0)
	state, shell, session := loginExpectRecordingSession(t, &now)
	submitEchoedLoginSecret(t, state, shell)

	// The remote echoes the reply in two reads.
	shell.say("s3")
	state.Wake()
	shell.say("cret\r\n")
	state.Wake()

	recorded := joinRecordedOutput(&session.term.recording)
	if strings.Contains(recorded, "s3cret") {
		t.Fatalf("recording leaked the echoed reply: %q", recorded)
	}
	if !strings.Contains(recorded, "Password: ") {
		t.Fatalf("ordinary prompt output was lost: %q", recorded)
	}
	// The screen is not filtered: the user still sees the echo.
	if screen := session.term.screen.Text(); !strings.Contains(screen, "s3cret") {
		t.Fatalf("screen lost the echo: %q", screen)
	}
}

func TestTerminalRecordingSettlesEchoedReplyOnDisconnect(t *testing.T) {
	now := time.Duration(0)
	state, shell, session := loginExpectRecordingSession(t, &now)
	submitEchoedLoginSecret(t, state, shell)

	// The whole reply arrives with the read that ends the shell, with no
	// trailing newline for the boundary rule to see.
	shell.say("s3cret")
	shell.end(nil)
	state.Wake()

	recorded := joinRecordedOutput(&session.term.recording)
	if strings.Contains(recorded, "s3cret") {
		t.Fatalf("recording leaked the reply at disconnect: %q", recorded)
	}
}
