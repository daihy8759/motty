package workbench

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/vivaui/viva/text"
	"motty/internal/i18n"
	"motty/internal/loginexpect"
)

func sampleLoginExpect() *loginexpect.Config {
	return &loginexpect.Config{
		Enabled: true,
		Steps: []loginexpect.Step{
			{ID: "one", Expect: "login: ", Send: "user", Timeout: 20 * time.Second, AppendEnter: true},
			{ID: "two", Expect: "Password: ", Sensitive: true, Timeout: 45 * time.Second, AppendEnter: true},
			{ID: "three", Expect: "ready", AppendEnter: false},
		},
	}
}

func TestLoginExpectSavedRoundTripClearsSensitiveResponse(t *testing.T) {
	cfg := sampleLoginExpect()
	// A sensitive rule that somehow carries a value must not have it saved.
	cfg.Steps[1].Send = "must-not-be-written"
	saved := encodeLoginExpect(cfg)
	if saved == nil || !saved.Enabled || len(saved.Steps) != 3 {
		t.Fatalf("saved=%+v", saved)
	}
	if saved.Steps[1].Send != "" {
		t.Fatalf("sensitive response was saved: %q", saved.Steps[1].Send)
	}
	data, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	var back savedLoginExpect
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	decoded := decodeLoginExpect(&back)
	if decoded == nil || !decoded.Enabled || len(decoded.Steps) != 3 {
		t.Fatalf("decoded=%+v", decoded)
	}
	if decoded.Steps[1].Sensitive != true || decoded.Steps[1].Send != "" {
		t.Fatalf("sensitive step=%+v", decoded.Steps[1])
	}
	if decoded.Steps[0].Timeout != 20*time.Second || decoded.Steps[0].AppendEnter != true {
		t.Fatalf("first step=%+v", decoded.Steps[0])
	}
	if decoded.Steps[2].AppendEnter != false {
		t.Fatalf("append enter lost: %+v", decoded.Steps[2])
	}
}

func TestLoginExpectDecodeDefaultsAndBackwardCompatibility(t *testing.T) {
	// A record from before rules existed has no field at all.
	if decodeLoginExpect(nil) != nil {
		t.Fatal("missing entry became a configuration")
	}
	// AppendEnter is absent: the form's default (true) applies.
	raw := `{"enabled":true,"steps":[{"expect":"Password:","sensitive":true}]}`
	var entry savedLoginExpect
	if err := json.Unmarshal([]byte(raw), &entry); err != nil {
		t.Fatal(err)
	}
	cfg := decodeLoginExpect(&entry)
	if cfg == nil || len(cfg.Steps) != 1 {
		t.Fatalf("cfg=%+v", cfg)
	}
	step := cfg.Steps[0]
	if !step.AppendEnter || step.Timeout != loginexpect.DefaultTimeoutSeconds*time.Second || step.Send != "" {
		t.Fatalf("step=%+v", step)
	}
}

func TestSavedHostCarriesLoginExpectThroughCatalogDecode(t *testing.T) {
	hosts, _ := decodeHosts([]savedHost{{
		ID: "h1", Label: "web", Address: "web.example.com", User: "me", Port: 22,
		LoginExpect: encodeLoginExpect(sampleLoginExpect()),
	}}, nil, 1)
	if len(hosts) != 1 || hosts[0].LoginExpect == nil {
		t.Fatalf("hosts=%+v", hosts)
	}
	if len(hosts[0].LoginExpect.Steps) != 3 || !hosts[0].LoginExpect.Enabled {
		t.Fatalf("login expect=%+v", hosts[0].LoginExpect)
	}
}

func TestHostEditorRoundTripsLoginExpect(t *testing.T) {
	var editor hostEditor
	editor.load(Host{Label: "web", Address: "web.example.com", Protocol: protocolSSH, LoginExpect: sampleLoginExpect()})
	host := editor.host(7)
	want := loginexpect.Normalize(*sampleLoginExpect())
	if host.LoginExpect == nil || !reflect.DeepEqual(*host.LoginExpect, want) {
		t.Fatalf("host login expect=%+v want=%+v", host.LoginExpect, want)
	}
}

func loginExpectTestState(t *testing.T) *State {
	t.Helper()
	return &State{messages: i18n.For(i18n.English)}
}

func loginExpectTestSession(t *testing.T, cfg *loginexpect.Config) (*State, *Session, *fakeShell) {
	t.Helper()
	state := loginExpectTestState(t)
	shell := &fakeShell{done: make(chan struct{})}
	term := newTerminalWithScrollback(80, 24, 100)
	term.shell = shell
	session := &Session{ID: 1, host: Host{Label: "web", LoginExpect: cfg}, term: term}
	state.sessions = append(state.sessions, *session)
	return state, &state.sessions[0], shell
}

func TestLoginExpectRuntimeSendsRulesInOrderAcrossReads(t *testing.T) {
	cfg := &loginexpect.Config{Enabled: true, Steps: []loginexpect.Step{
		{Expect: "login: ", Send: "user", AppendEnter: true, Timeout: time.Second},
		{Expect: "Password: ", Send: "secret", AppendEnter: true, Timeout: time.Second},
	}}
	state, session, shell := loginExpectTestSession(t, cfg)
	state.startLoginExpect(session)
	if string(shell.input) != "" {
		t.Fatalf("sent before a prompt: %q", shell.input)
	}
	state.feedLoginExpect(session, []byte("banner\nlo"))
	state.feedLoginExpect(session, []byte("gin: "))
	if string(shell.input) != "user\r" {
		t.Fatalf("after first prompt: %q", shell.input)
	}
	state.feedLoginExpect(session, []byte("Password: "))
	if string(shell.input) != "user\rsecret\r" {
		t.Fatalf("after second prompt: %q", shell.input)
	}
	if session.loginExpect != nil {
		t.Fatal("runner should be done")
	}
}

func TestLoginExpectRuntimeAsksForSensitiveResponse(t *testing.T) {
	cfg := &loginexpect.Config{Enabled: true, Steps: []loginexpect.Step{
		{Expect: "", Sensitive: true, AppendEnter: true, Timeout: time.Second},
	}}
	state, session, shell := loginExpectTestSession(t, cfg)
	state.startLoginExpect(session)
	if session.loginExpect == nil || !session.loginExpect.Awaiting() {
		t.Fatal("sensitive rule did not ask")
	}
	if state.modal != modalLoginExpectSecret || session.loginExpectAsk == nil || state.modalSession != session.ID {
		t.Fatalf("modal=%v session=%d ask=%+v", state.modal, state.modalSession, session.loginExpectAsk)
	}
	if string(shell.input) != "" {
		t.Fatalf("sent before the answer: %q", shell.input)
	}
	state.provideLoginExpectSecret(session, "s3cret")
	if string(shell.input) != "s3cret\r" {
		t.Fatalf("answer=%q", shell.input)
	}
	if session.loginExpect != nil {
		t.Fatal("runner should be done")
	}
}

func TestLoginExpectRuntimeTimeoutStopsAndLeavesManualShell(t *testing.T) {
	now := time.Duration(0)
	state, session, shell := loginExpectTestSession(t, &loginexpect.Config{Enabled: true, Steps: []loginexpect.Step{
		{Expect: "never", Send: "x", Timeout: time.Second},
		{Expect: "", Send: "later"},
	}})
	state.options.Now = func() time.Duration { return now }
	state.startLoginExpect(session)
	if session.loginExpect == nil {
		t.Fatal("runner did not start")
	}
	now = time.Second
	state.driveLoginExpect(session, state.loginExpectNow())
	if session.loginExpect != nil {
		t.Fatal("timeout must drop the runner")
	}
	if string(shell.input) != "" {
		t.Fatalf("sent after timeout: %q", shell.input)
	}
	// The shell is still there for the user to type into.
	shell.mu.Lock()
	defer shell.mu.Unlock()
	if shell.closed {
		t.Fatal("timeout closed the shell")
	}
}

func TestLoginExpectStartsWithEachNewShell(t *testing.T) {
	cfg := &loginexpect.Config{Enabled: true, Steps: []loginexpect.Step{
		{Expect: "login: ", Send: "user", AppendEnter: true, Timeout: time.Second},
	}}
	state, session, shell := loginExpectTestSession(t, cfg)
	state.startLoginExpect(session)
	state.feedLoginExpect(session, []byte("login: "))
	if string(shell.input) != "user\r" {
		t.Fatalf("first shell=%q", shell.input)
	}
	// A reconnect gives a fresh shell and repeats the rules from the first one.
	fresh := &fakeShell{done: make(chan struct{})}
	session.term.shell = fresh
	state.startLoginExpect(session)
	state.feedLoginExpect(session, []byte("login: "))
	if string(fresh.input) != "user\r" {
		t.Fatalf("reconnected shell=%q", fresh.input)
	}
}

func TestHostCatalogExportRoundTripsLoginExpect(t *testing.T) {
	host := Host{Label: "web", Address: "web.example.com", User: "me", Port: 22, LoginExpect: sampleLoginExpect()}
	entry := savedHostFromHost(host)
	if entry.LoginExpect == nil {
		t.Fatal("export dropped login expect")
	}
	state := loginExpectTestState(t)
	imported, ok := state.hostFromCatalogEntry(entry)
	if !ok || imported.LoginExpect == nil {
		t.Fatalf("import ok=%v login=%+v", ok, imported.LoginExpect)
	}
	if !imported.LoginExpect.Enabled || len(imported.LoginExpect.Steps) != 3 {
		t.Fatalf("imported=%+v", imported.LoginExpect)
	}
	if imported.LoginExpect.Steps[1].Send != "" {
		t.Fatal("a sensitive response came back from an import")
	}
}

func sensitiveLoginExpectConfig() *loginexpect.Config {
	return &loginexpect.Config{Enabled: true, Steps: []loginexpect.Step{
		{Expect: "", Sensitive: true, AppendEnter: true, Timeout: time.Second},
	}}
}

func loginExpectSessionPair(t *testing.T) (*State, *Session, *Session, *fakeShell, *fakeShell) {
	t.Helper()
	state := loginExpectTestState(t)
	state.options.Now = func() time.Duration { return 0 }
	newSession := func(id uint32) (*Session, *fakeShell) {
		shell := &fakeShell{done: make(chan struct{})}
		term := newTerminalWithScrollback(80, 24, 100)
		term.shell = shell
		return &Session{ID: id, host: Host{Label: "host", LoginExpect: sensitiveLoginExpectConfig()}, term: term}, shell
	}
	first, firstShell := newSession(1)
	second, secondShell := newSession(2)
	state.sessions = append(state.sessions, *first, *second)
	return state, &state.sessions[0], &state.sessions[1], firstShell, secondShell
}

func TestSensitivePromptsNeverOverwriteTheOpenSession(t *testing.T) {
	state, first, second, firstShell, secondShell := loginExpectSessionPair(t)
	state.startLoginExpect(first)
	if state.modal != modalLoginExpectSecret || state.modalSession != first.ID {
		t.Fatalf("first prompt not shown: modal=%v session=%d", state.modal, state.modalSession)
	}
	first.loginExpectAsk.editor.Insert("par")

	// A second shell asks while the first dialog is open. It must not touch the
	// open prompt or the text already typed there.
	state.startLoginExpect(second)
	if state.modalSession != first.ID {
		t.Fatalf("background request stole the dialog: session=%d", state.modalSession)
	}
	if first.loginExpectAsk == nil || first.loginExpectAsk.editor.String() != "par" {
		t.Fatalf("open editor was overwritten: %+v", first.loginExpectAsk)
	}
	if second.loginExpectAsk == nil {
		t.Fatal("second request was not remembered")
	}

	// Submitting the first sends only to the first shell, then shows the second.
	state.clickLoginExpectSecret(hitLoginExpectSubmit)
	if got := string(firstShell.input); got != "par\r" {
		t.Fatalf("first shell input=%q", got)
	}
	if got := string(secondShell.input); got != "" {
		t.Fatalf("second shell received the first credential: %q", got)
	}
	if state.modal != modalLoginExpectSecret || state.modalSession != second.ID {
		t.Fatalf("second prompt not shown after submit: modal=%v session=%d", state.modal, state.modalSession)
	}

	second.loginExpectAsk.editor.Insert("bee")
	state.clickLoginExpectSecret(hitLoginExpectSubmit)
	if got := string(secondShell.input); got != "bee\r" {
		t.Fatalf("second shell input=%q", got)
	}
	if state.modal != modalNone {
		t.Fatalf("modal remained after both answers: %v", state.modal)
	}
}

func TestCancelingOneWaitingPromptKeepsAnother(t *testing.T) {
	state, first, second, firstShell, _ := loginExpectSessionPair(t)
	state.startLoginExpect(first)
	first.loginExpectAsk.editor.Insert("partial")
	state.startLoginExpect(second)
	if second.loginExpectAsk == nil {
		t.Fatal("second request missing before cancel")
	}

	state.clickLoginExpectSecret(hitLoginExpectCancel)
	if first.loginExpect != nil || first.loginExpectAsk != nil {
		t.Fatal("cancelled session kept its request")
	}
	if got := string(firstShell.input); got != "" {
		t.Fatalf("cancelled session sent %q", got)
	}
	if state.modal != modalLoginExpectSecret || state.modalSession != second.ID {
		t.Fatalf("other waiting prompt not shown: modal=%v session=%d", state.modal, state.modalSession)
	}
	if second.loginExpect == nil || !second.loginExpect.Awaiting() || second.loginExpectAsk == nil {
		t.Fatal("other waiting request was lost")
	}
}

func TestDisconnectingOneWaitingSessionRemovesOnlyItsRequest(t *testing.T) {
	state, first, second, _, _ := loginExpectSessionPair(t)
	state.startLoginExpect(first)
	first.loginExpectAsk.editor.Insert("keep typing")
	state.startLoginExpect(second)

	// The shell that is not on screen disconnects: its request goes away and the
	// open dialog is untouched.
	state.stopLoginExpect(second)
	if second.loginExpect != nil || second.loginExpectAsk != nil {
		t.Fatal("disconnected session kept its request")
	}
	if state.modal != modalLoginExpectSecret || state.modalSession != first.ID {
		t.Fatalf("open prompt was disturbed: modal=%v session=%d", state.modal, state.modalSession)
	}
	if first.loginExpectAsk.editor.String() != "keep typing" {
		t.Fatalf("open editor changed: %q", first.loginExpectAsk.editor.String())
	}

	// Now the open session disconnects: it is removed and the remaining waiting
	// request takes over.
	state.startLoginExpect(second) // let the second ask again for this half
	if second.loginExpectAsk == nil {
		t.Fatal("second request missing")
	}
	state.stopLoginExpect(first)
	if first.loginExpectAsk != nil {
		t.Fatal("open session kept its request after disconnect")
	}
	if state.modal != modalLoginExpectSecret || state.modalSession != second.ID {
		t.Fatalf("remaining prompt not shown: modal=%v session=%d", state.modal, state.modalSession)
	}
}

func TestLoginExpectDelaySavedAndDefaultsToZero(t *testing.T) {
	cfg := &loginexpect.Config{Enabled: true, Steps: []loginexpect.Step{
		{Expect: "login: ", Send: "user", Delay: 750 * time.Millisecond, Timeout: 20 * time.Second},
		{Expect: "ready", Send: "go", Timeout: 20 * time.Second},
	}}
	saved := encodeLoginExpect(cfg)
	if saved == nil || len(saved.Steps) != 2 {
		t.Fatalf("saved=%+v", saved)
	}
	if saved.Steps[0].DelayMilliseconds != 750 {
		t.Fatalf("first delay=%d", saved.Steps[0].DelayMilliseconds)
	}
	if saved.Steps[1].DelayMilliseconds != 0 {
		t.Fatalf("default delay=%d", saved.Steps[1].DelayMilliseconds)
	}
	data, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	var back savedLoginExpect
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	decoded := decodeLoginExpect(&back)
	if decoded == nil || len(decoded.Steps) != 2 {
		t.Fatalf("decoded=%+v", decoded)
	}
	if decoded.Steps[0].Delay != 750*time.Millisecond {
		t.Fatalf("round-trip delay=%v", decoded.Steps[0].Delay)
	}
	if decoded.Steps[1].Delay != 0 {
		t.Fatalf("round-trip default delay=%v", decoded.Steps[1].Delay)
	}
}

func TestLoginExpectLegacyJSONWithoutDelayLoadsAsZero(t *testing.T) {
	// A record written before the delay field existed must still load, with no
	// delay, exactly like the old behaviour.
	raw := `{"enabled":true,"steps":[{"expect":"login: ","send":"user","timeout_seconds":20}]}`
	var entry savedLoginExpect
	if err := json.Unmarshal([]byte(raw), &entry); err != nil {
		t.Fatal(err)
	}
	cfg := decodeLoginExpect(&entry)
	if cfg == nil || len(cfg.Steps) != 1 {
		t.Fatalf("cfg=%+v", cfg)
	}
	if cfg.Steps[0].Delay != 0 {
		t.Fatalf("legacy rule gained a delay: %v", cfg.Steps[0].Delay)
	}
}

func TestSavedLoginExpectDifferenceDetectsDelay(t *testing.T) {
	base := &loginexpect.Config{Enabled: true, Steps: []loginexpect.Step{{Expect: "x", Send: "y"}}}
	withDelay := &loginexpect.Config{Enabled: true, Steps: []loginexpect.Step{{Expect: "x", Send: "y", Delay: 100 * time.Millisecond}}}
	if sameSavedLoginExpect(encodeLoginExpect(base), encodeLoginExpect(withDelay)) {
		t.Fatal("a delay change was not seen as a change")
	}
	if !sameSavedLoginExpect(encodeLoginExpect(withDelay), encodeLoginExpect(withDelay)) {
		t.Fatal("identical delay configurations differed")
	}
}

func TestLoginExpectStepEditorValidatesDelay(t *testing.T) {
	state := loginExpectTestState(t)
	m := state.messages.LoginExpect

	state.openLoginExpectStep(-1)
	state.loginExpectStep.expect.Insert("login: ")
	state.loginExpectStep.send.Insert("user")
	state.loginExpectStep.delay = text.Editor{}
	state.loginExpectStep.delay.Insert("-5")
	state.saveLoginExpectStep()
	if len(state.editor.loginExpect.Steps) != 0 {
		t.Fatal("a negative delay was saved")
	}
	if state.loginExpectStep.err != m.ErrDelay {
		t.Fatalf("error=%q want %q", state.loginExpectStep.err, m.ErrDelay)
	}

	// A valid value is stored in milliseconds.
	state.loginExpectStep.delay = text.Editor{}
	state.loginExpectStep.delay.Insert("250")
	state.saveLoginExpectStep()
	if len(state.editor.loginExpect.Steps) != 1 {
		t.Fatalf("steps=%+v", state.editor.loginExpect.Steps)
	}
	if got := state.editor.loginExpect.Steps[0].Delay; got != 250*time.Millisecond {
		t.Fatalf("delay=%v", got)
	}

	// An out-of-range value is clamped rather than rejected or overflowed.
	state.openLoginExpectStep(-1)
	state.loginExpectStep.expect.Insert("ready")
	state.loginExpectStep.send.Insert("go")
	state.loginExpectStep.delay = text.Editor{}
	state.loginExpectStep.delay.Insert("999999999")
	state.saveLoginExpectStep()
	steps := state.editor.loginExpect.Steps
	if len(steps) != 2 {
		t.Fatalf("steps=%+v", steps)
	}
	if got := steps[1].Delay; got != loginexpect.MaxDelay {
		t.Fatalf("clamped delay=%v want %v", got, loginexpect.MaxDelay)
	}
}

func TestLoginExpectRuntimeWaitsDelayBeforeSendingOnce(t *testing.T) {
	now := time.Duration(0)
	cfg := &loginexpect.Config{Enabled: true, Steps: []loginexpect.Step{
		{Expect: "login: ", Send: "user", AppendEnter: true, Delay: 300 * time.Millisecond, Timeout: time.Second},
	}}
	state, session, shell := loginExpectTestSession(t, cfg)
	state.options.Now = func() time.Duration { return now }
	state.startLoginExpect(session)
	state.feedLoginExpect(session, []byte("login: "))
	if string(shell.input) != "" {
		t.Fatalf("sent before the delay: %q", shell.input)
	}
	runner := session.loginExpect
	if runner == nil || runner.DelayDeadline().IsZero() {
		t.Fatalf("no delay deadline: runner=%+v", runner)
	}

	now = 299 * time.Millisecond
	state.driveLoginExpect(session, state.loginExpectNow())
	if string(shell.input) != "" {
		t.Fatalf("sent before the deadline: %q", shell.input)
	}

	now = 300 * time.Millisecond
	state.driveLoginExpect(session, state.loginExpectNow())
	if string(shell.input) != "user\r" {
		t.Fatalf("reply=%q", shell.input)
	}
	if session.loginExpect != nil {
		t.Fatal("runner should be done after the reply")
	}

	// A later frame with nothing new must not send the reply a second time.
	now = time.Second
	state.driveLoginExpect(session, state.loginExpectNow())
	state.feedLoginExpect(session, []byte("ignored"))
	if string(shell.input) != "user\r" {
		t.Fatalf("reply was sent more than once: %q", shell.input)
	}
}

func TestLoginExpectRuntimeStopDuringDelaySendsNothing(t *testing.T) {
	now := time.Duration(0)
	cfg := &loginexpect.Config{Enabled: true, Steps: []loginexpect.Step{
		{Expect: "login: ", Send: "user", AppendEnter: true, Delay: 500 * time.Millisecond, Timeout: time.Second},
	}}
	state, session, shell := loginExpectTestSession(t, cfg)
	state.options.Now = func() time.Duration { return now }
	state.startLoginExpect(session)
	state.feedLoginExpect(session, []byte("login: "))
	if session.loginExpect == nil || session.loginExpect.DelayDeadline().IsZero() {
		t.Fatal("rule did not reach its delay")
	}

	// A disconnect, tab close or reconnect drops the run and its pending delay.
	state.stopLoginExpect(session)
	if session.loginExpect != nil {
		t.Fatal("stopped session kept its runner")
	}
	now = time.Second
	state.driveLoginExpect(session, state.loginExpectNow())
	state.feedLoginExpect(session, []byte("login: "))
	if string(shell.input) != "" {
		t.Fatalf("a stopped delay wrote %q", shell.input)
	}
}

// TestLoginExpectRuntimeDelaySendsOnPumpWithoutNewOutput drives the delay the
// way the window does: through pump (what Wake calls each frame), not by calling
// driveLoginExpect directly, and with no further remote output after the prompt.
func TestLoginExpectRuntimeDelaySendsOnPumpWithoutNewOutput(t *testing.T) {
	now := time.Duration(0)
	state := newTestState(t, testOptions(t))
	state.options.Now = func() time.Duration { return now }
	state.options.Invalidate = func() {}

	cfg := &loginexpect.Config{Enabled: true, Steps: []loginexpect.Step{
		{Expect: "login: ", Send: "user", AppendEnter: true, Delay: 400 * time.Millisecond, Timeout: time.Second},
	}}
	shell := &fakeShell{done: make(chan struct{})}
	term := newTerminalWithScrollback(80, 24, 100)
	term.shell = shell
	state.sessions = append(state.sessions, Session{ID: 1, host: Host{Label: "web", LoginExpect: cfg}, term: term})
	session := &state.sessions[0]
	state.startLoginExpect(session)

	// The prompt is ordinary remote output, so it takes the same pump path as
	// every other byte the shell prints.
	shell.say("login: ")
	state.pump(session)
	if got := string(shell.input); got != "" {
		t.Fatalf("sent before the delay: %q", got)
	}
	if session.loginExpect == nil || session.loginExpect.DelayDeadline().IsZero() {
		t.Fatal("rule did not enter its delay")
	}

	// No new output arrives. A frame just moves the clock and pumps again.
	now = 399 * time.Millisecond
	state.pump(session)
	if got := string(shell.input); got != "" {
		t.Fatalf("sent before the deadline: %q", got)
	}

	now = 400 * time.Millisecond
	state.pump(session)
	if got := string(shell.input); got != "user\r" {
		t.Fatalf("reply=%q", got)
	}
	if session.loginExpect != nil {
		t.Fatal("runner should be done after the reply")
	}

	// One more frame must not send the reply again.
	now = time.Second
	state.pump(session)
	if got := string(shell.input); got != "user\r" {
		t.Fatalf("reply was sent more than once: %q", got)
	}
}

// TestLoginExpectReplyWithColonsSurvivesEditorAndRuntime saves a rule whose
// reply contains colons through the same editor the host dialog uses, reads it
// back, and runs it. The shell must receive every byte: a colon is never a
// delimiter, and the write counts as input so a shell that ends after the
// reply is not mistaken for a silent one.
func TestLoginExpectReplyWithColonsSurvivesEditorAndRuntime(t *testing.T) {
	state := loginExpectTestState(t)
	state.editor = hostEditor{}
	state.editor.load(Host{Label: "web", Address: "web.example.com", Protocol: protocolSSH})
	state.openLoginExpectStep(-1)
	state.loginExpectStep.expect.Insert("login: ")
	state.loginExpectStep.send.Insert("user:pass:word")
	state.saveLoginExpectStep()
	state.editor.loginExpect.Enabled = true

	host := state.editor.host(1)
	if host.LoginExpect == nil || len(host.LoginExpect.Steps) != 1 {
		t.Fatalf("login expect=%+v", host.LoginExpect)
	}
	if got := host.LoginExpect.Steps[0].Send; got != "user:pass:word" {
		t.Fatalf("saved reply=%q", got)
	}

	shell := &fakeShell{done: make(chan struct{})}
	term := newTerminalWithScrollback(80, 24, 100)
	term.shell = shell
	state.sessions = append(state.sessions, Session{ID: 1, host: host, term: term})
	session := &state.sessions[0]
	state.startLoginExpect(session)
	state.feedLoginExpect(session, []byte("login: "))
	if got := string(shell.input); got != "user:pass:word\r" {
		t.Fatalf("shell got %q, want the whole reply", got)
	}
	if !term.inputSent {
		t.Fatal("the login reply was not counted as input")
	}
	if session.loginExpect != nil {
		t.Fatal("runner should be done")
	}
}

// TestLoginExpectSensitiveReplyWithColonsIsSentWhole covers the runtime answer
// path: the text typed into the prompt is not split or trimmed at a colon.
func TestLoginExpectSensitiveReplyWithColonsIsSentWhole(t *testing.T) {
	cfg := &loginexpect.Config{Enabled: true, Steps: []loginexpect.Step{
		{Expect: "Password: ", Sensitive: true, AppendEnter: true, Timeout: time.Second},
	}}
	state, session, shell := loginExpectTestSession(t, cfg)
	state.startLoginExpect(session)
	state.feedLoginExpect(session, []byte("Password: "))
	if session.loginExpectAsk == nil {
		t.Fatal("sensitive prompt did not open")
	}
	session.loginExpectAsk.editor.Insert("user:pass:word")
	state.provideLoginExpectSecret(session, session.loginExpectAsk.editor.String())
	if got := string(shell.input); got != "user:pass:word\r" {
		t.Fatalf("shell got %q, want the whole answer", got)
	}
	if !session.term.inputSent {
		t.Fatal("the sensitive reply was not counted as input")
	}
}
