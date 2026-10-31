package loginexpect

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func collect(t *testing.T, r *Runner, now time.Time, output []byte) ([]string, Event) {
	t.Helper()
	r.Feed(output)
	var sent []string
	write := func(payload []byte, sensitive bool) bool {
		sent = append(sent, string(payload))
		return true
	}
	event := r.Pump(now, write)
	for event.Kind == EventWait {
		// Nothing more can run without output in this helper.
		break
	}
	return sent, event
}

func TestOrderedPromptsAcrossChunks(t *testing.T) {
	r := New([]Step{
		{Expect: "login:", Send: "user", AppendEnter: true, Timeout: time.Second},
		{Expect: "Password:", Send: "secret", AppendEnter: true, Timeout: time.Second},
	})
	now := time.Unix(1, 0)
	var sent []string
	write := func(p []byte, sensitive bool) bool {
		if sensitive {
			t.Fatalf("ordinary rule reported sensitive")
		}
		sent = append(sent, string(p))
		return true
	}
	// The two prompts arrive fragmented, and the second one is already in the
	// same read as the tail of the first.
	for _, chunk := range []string{"log", "in:Password", ":"} {
		r.Feed([]byte(chunk))
		if ev := r.Pump(now, write); ev.Kind == EventFailed {
			t.Fatalf("advance failed: %v", ev.Err)
		}
	}
	if !r.Done() {
		t.Fatalf("runner not done at %d", r.Index())
	}
	if !reflect.DeepEqual(sent, []string{"user\r", "secret\r"}) {
		t.Fatalf("sent=%q", sent)
	}
}

func TestEmptyExpectSendsImmediatelyWithoutWaiting(t *testing.T) {
	r := New([]Step{{Send: "x", AppendEnter: true}})
	var sent []string
	ev := r.Pump(time.Unix(1, 0), func(p []byte, sensitive bool) bool {
		sent = append(sent, string(p))
		return true
	})
	if ev.Kind != EventDone || !r.Done() {
		t.Fatalf("event=%+v done=%v", ev, r.Done())
	}
	if !reflect.DeepEqual(sent, []string{"x\r"}) {
		t.Fatalf("sent=%q", sent)
	}
}

func TestTimeoutStopsAtTheDeadlineAndKeepsLaterRulesUnrun(t *testing.T) {
	now := time.Unix(1, 0)
	r := New([]Step{
		{Expect: "prompt", Timeout: time.Second},
		{Send: "later"},
	})
	if ev := r.Pump(now, func([]byte, bool) bool { return true }); ev.Kind != EventWait {
		t.Fatalf("want wait, got %+v", ev)
	}
	if got := r.Deadline(); !got.Equal(now.Add(time.Second)) {
		t.Fatalf("deadline=%v", got)
	}
	ev := r.Pump(now.Add(time.Second), func([]byte, bool) bool {
		t.Fatal("nothing may be sent after a timeout")
		return true
	})
	if ev.Kind != EventFailed || !errors.Is(ev.Err, ErrTimeout) || !errors.Is(r.Failed(), ErrTimeout) {
		t.Fatalf("event=%+v failed=%v", ev, r.Failed())
	}
}

func TestWriteFailureStopsTheRun(t *testing.T) {
	r := New([]Step{{Send: "x"}, {Send: "y"}})
	ev := r.Pump(time.Unix(1, 0), func([]byte, bool) bool { return false })
	if ev.Kind != EventFailed || !errors.Is(ev.Err, ErrWrite) {
		t.Fatalf("event=%+v", ev)
	}
}

func TestSensitiveRuleAsksAtRuntimeAndMarksTheWrite(t *testing.T) {
	r := NewConfig(Config{Enabled: true, Steps: []Step{
		{Expect: "login: ", Send: "user", AppendEnter: true},
		{Expect: "Password: ", Sensitive: true, AppendEnter: true, Send: "must-not-be-used"},
	}})
	now := time.Unix(1, 0)
	type write struct {
		data      string
		sensitive bool
	}
	var writes []write
	writer := func(p []byte, sensitive bool) bool {
		writes = append(writes, write{string(p), sensitive})
		return true
	}
	r.Feed([]byte("login: Password: "))
	ev := r.Pump(now, writer)
	if ev.Kind != EventSecret || ev.Step != 1 {
		t.Fatalf("event=%+v", ev)
	}
	if !r.Awaiting() || r.Deadline().IsZero() == false {
		t.Fatalf("awaiting=%v deadline=%v", r.Awaiting(), r.Deadline())
	}
	// The saved "must-not-be-used" value never reaches the shell.
	if !reflect.DeepEqual(writes, []write{{"user\r", false}}) {
		t.Fatalf("writes before secret=%+v", writes)
	}
	ev = r.ProvideSecret("s3cret", now, writer)
	if ev.Kind != EventDone {
		t.Fatalf("event=%+v", ev)
	}
	if !reflect.DeepEqual(writes, []write{{"user\r", false}, {"s3cret\r", true}}) {
		t.Fatalf("writes=%+v", writes)
	}
}

func TestSensitiveConfigNormalizationDropsSavedResponse(t *testing.T) {
	cfg := Normalize(Config{Enabled: true, Steps: []Step{
		{Expect: "Password:", Send: "hidden", Sensitive: true},
	}})
	if cfg.Steps[0].Send != "" {
		t.Fatalf("sensitive send survived normalization: %q", cfg.Steps[0].Send)
	}
}

func TestRepeatedPromptMustArriveAgain(t *testing.T) {
	// A second rule with the same wait must not match the bytes the first rule
	// consumed; it needs a new occurrence in later output.
	r := New([]Step{
		{Expect: "login: ", Send: "user", AppendEnter: true},
		{Expect: "login: ", Send: "second", AppendEnter: true},
	})
	now := time.Unix(1, 0)
	var sent []string
	write := func(p []byte, sensitive bool) bool { sent = append(sent, string(p)); return true }
	r.Feed([]byte("login: login: "))
	ev := r.Pump(now, write)
	if ev.Kind != EventDone {
		t.Fatalf("event=%+v", ev)
	}
	if !reflect.DeepEqual(sent, []string{"user\r", "second\r"}) {
		t.Fatalf("sent=%q", sent)
	}

	r = New([]Step{
		{Expect: "login: ", Send: "user", AppendEnter: true},
		{Expect: "login: ", Send: "second", AppendEnter: true},
	})
	r.Feed([]byte("login: "))
	if ev := r.Pump(now, write); ev.Kind != EventWait {
		t.Fatalf("event=%+v", ev)
	}
	r.Feed([]byte("banner login: "))
	if ev := r.Pump(now, write); ev.Kind != EventDone {
		t.Fatalf("event=%+v", ev)
	}
}

func TestLongPromptSplitAcrossReadsSurvivesBufferTrimming(t *testing.T) {
	prompt := strings.Repeat("a", 800) + "PROMPT"
	r := New([]Step{{Expect: prompt, Send: "ok", Timeout: time.Minute, AppendEnter: true}})
	now := time.Unix(1, 0)
	// A flood of unrelated bytes, then the prompt in two pieces across the trim.
	r.Feed([]byte(strings.Repeat("x", maxBuffer*2)))
	if ev := r.Pump(now, func([]byte, bool) bool { return true }); ev.Kind != EventWait {
		t.Fatalf("event=%+v", ev)
	}
	half := len(prompt) / 2
	r.Feed([]byte(prompt[:half]))
	if ev := r.Pump(now, func([]byte, bool) bool { return true }); ev.Kind != EventWait {
		t.Fatalf("event=%+v", ev)
	}
	var sent []string
	r.Feed([]byte(prompt[half:]))
	if ev := r.Pump(now, func(p []byte, _ bool) bool { sent = append(sent, string(p)); return true }); ev.Kind != EventDone {
		t.Fatalf("event=%+v", ev)
	}
	if !reflect.DeepEqual(sent, []string{"ok\r"}) {
		t.Fatalf("sent=%q", sent)
	}
}

func TestCancelStopsWithoutMoreWrites(t *testing.T) {
	r := New([]Step{{Expect: "never", Send: "x", Timeout: time.Minute}})
	r.Pump(time.Unix(1, 0), func([]byte, bool) bool { return true })
	r.Cancel()
	ev := r.Pump(time.Unix(2, 0), func([]byte, bool) bool {
		t.Fatal("cancelled run must not write")
		return true
	})
	if ev.Kind != EventFailed || !errors.Is(ev.Err, ErrCanceled) {
		t.Fatalf("event=%+v", ev)
	}
}

func TestDecodeTextDecodesOnceAndKeepsUnknownEscapes(t *testing.T) {
	got := DecodeText(`\r\n\t\e\x41\\\q`)
	want := "\r\n\t\x1bA\\" + `\q`
	if got != want {
		t.Fatalf("decode=%q want=%q", got, want)
	}
	if DecodeText(`\\r`) != `\r` {
		t.Fatalf("a doubled backslash decoded twice")
	}
}

func TestNormalizeBoundsAndRepairs(t *testing.T) {
	cfg := Normalize(Config{Enabled: true, Steps: []Step{
		{Expect: "a", Timeout: time.Hour * 9},
		{Expect: "b", Timeout: time.Millisecond},
		{Expect: "", Send: ""}, // empty rule dropped
		{Expect: "c", Send: "x"},
		{Expect: "d", Send: "y"},
	}})
	if len(cfg.Steps) != 4 {
		t.Fatalf("steps=%d", len(cfg.Steps))
	}
	if cfg.Steps[0].Timeout != MaxTimeoutSeconds*time.Second {
		t.Fatalf("long timeout=%v", cfg.Steps[0].Timeout)
	}
	if cfg.Steps[1].Timeout != DefaultTimeoutSeconds*time.Second {
		t.Fatalf("short timeout=%v", cfg.Steps[1].Timeout)
	}
	seen := map[string]bool{}
	for _, step := range cfg.Steps {
		if step.ID == "" || seen[step.ID] {
			t.Fatalf("bad id %q", step.ID)
		}
		seen[step.ID] = true
	}
}

func TestFeedKeepsOutputForTheCaller(t *testing.T) {
	// The runner copies what it needs; it must not mutate the caller's slice,
	// because the same bytes still go to the terminal.
	r := New([]Step{{Expect: "x", Send: "y"}})
	input := []byte("hello x")
	original := string(input)
	r.Feed(input)
	if string(input) != original {
		t.Fatalf("input mutated: %q", input)
	}
}

func TestLegacyAdvanceEntryPointStillWorks(t *testing.T) {
	now := time.Unix(1, 0)
	r := New([]Step{{Expect: "login:", Send: "user", AppendEnter: true}})
	var sent []string
	write := func(p []byte) bool { sent = append(sent, string(p)); return true }
	if err := r.Advance(now, []byte("login:"), write); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sent, []string{"user\r"}) || !r.Done() {
		t.Fatalf("sent=%q done=%v", sent, r.Done())
	}
	r = New([]Step{{Expect: "prompt", Timeout: time.Second}})
	if err := r.Advance(now, nil, write); err != nil {
		t.Fatalf("wait returned %v", err)
	}
	if err := r.Advance(now.Add(time.Second), nil, write); !errors.Is(err, ErrTimeout) {
		t.Fatalf("timeout err=%v", err)
	}
	r = New([]Step{{Send: "x"}})
	if err := r.Advance(now, nil, func([]byte) bool { return false }); !errors.Is(err, ErrWrite) {
		t.Fatalf("write err=%v", err)
	}
}

func TestDelayDoesNotSendBeforeDeadlineAndSendsOnce(t *testing.T) {
	now := time.Unix(1, 0)
	r := New([]Step{{Expect: "prompt", Send: "reply", AppendEnter: true, Delay: 500 * time.Millisecond}})
	var sent []string
	write := func(p []byte, sensitive bool) bool {
		sent = append(sent, string(p))
		return true
	}
	r.Feed([]byte("prompt"))
	ev := r.Pump(now, write)
	if ev.Kind != EventWait || len(sent) != 0 {
		t.Fatalf("event=%+v sent=%q", ev, sent)
	}
	if got := r.DelayDeadline(); !got.Equal(now.Add(500 * time.Millisecond)) {
		t.Fatalf("delay deadline=%v", got)
	}
	if ev := r.Pump(now.Add(499*time.Millisecond), write); ev.Kind != EventWait || len(sent) != 0 {
		t.Fatalf("early event=%+v sent=%q", ev, sent)
	}
	if ev := r.Pump(now.Add(500*time.Millisecond), write); ev.Kind != EventDone {
		t.Fatalf("due event=%+v", ev)
	}
	if !reflect.DeepEqual(sent, []string{"reply\r"}) {
		t.Fatalf("sent=%q", sent)
	}
	// A done run must not send its reply again on a later frame.
	if ev := r.Pump(now.Add(time.Second), write); ev.Kind != EventDone {
		t.Fatalf("repeat event=%+v", ev)
	}
	if len(sent) != 1 {
		t.Fatalf("reply sent %d times", len(sent))
	}
}

func TestDelayKeepsOutputArrivingDuringTheWait(t *testing.T) {
	now := time.Unix(1, 0)
	r := New([]Step{
		{Expect: "one", Send: "a", Delay: time.Second, Timeout: time.Second},
		{Expect: "two", Send: "b", Timeout: time.Second},
	})
	var sent []string
	write := func(p []byte, sensitive bool) bool {
		sent = append(sent, string(p))
		return true
	}
	r.Feed([]byte("one"))
	if ev := r.Pump(now, write); ev.Kind != EventWait || len(sent) != 0 {
		t.Fatalf("event=%+v sent=%q", ev, sent)
	}
	// The next prompt arrives while the first reply waits out its delay; it must
	// still be there for the next rule.
	r.Feed([]byte("two"))
	if ev := r.Pump(now.Add(time.Second), write); ev.Kind != EventDone {
		t.Fatalf("event=%+v", ev)
	}
	if !reflect.DeepEqual(sent, []string{"a", "b"}) {
		t.Fatalf("sent=%q", sent)
	}
}

func TestCancelDuringDelaySendsNothing(t *testing.T) {
	now := time.Unix(1, 0)
	r := New([]Step{{Expect: "prompt", Send: "x", Delay: time.Second}})
	r.Feed([]byte("prompt"))
	if ev := r.Pump(now, func([]byte, bool) bool { return true }); ev.Kind != EventWait {
		t.Fatalf("event=%+v", ev)
	}
	r.Cancel()
	ev := r.Pump(now.Add(2*time.Second), func([]byte, bool) bool {
		t.Fatal("a cancelled delay must not write")
		return true
	})
	if ev.Kind != EventFailed || !errors.Is(ev.Err, ErrCanceled) {
		t.Fatalf("event=%+v", ev)
	}
	if !r.DelayDeadline().IsZero() {
		t.Fatal("cancel kept a delay deadline")
	}
}

func TestSensitiveReplyWaitsOutRemainingDelay(t *testing.T) {
	now := time.Unix(1, 0)
	r := NewConfig(Config{Enabled: true, Steps: []Step{
		{Expect: "Password: ", Sensitive: true, AppendEnter: true, Delay: 2 * time.Second},
	}})
	type write struct {
		data      string
		sensitive bool
	}
	var writes []write
	writer := func(p []byte, sensitive bool) bool {
		writes = append(writes, write{string(p), sensitive})
		return true
	}
	r.Feed([]byte("Password: "))
	// The ask happens at once; the delay governs the send, not the question.
	if ev := r.Pump(now, writer); ev.Kind != EventSecret || len(writes) != 0 {
		t.Fatalf("event=%+v writes=%+v", ev, writes)
	}
	// The answer arrives halfway through the delay and must not overtake it.
	if ev := r.ProvideSecret("pw", now.Add(500*time.Millisecond), writer); ev.Kind != EventWait || len(writes) != 0 {
		t.Fatalf("event=%+v writes=%+v", ev, writes)
	}
	if ev := r.Pump(now.Add(1999*time.Millisecond), writer); ev.Kind != EventWait || len(writes) != 0 {
		t.Fatalf("still-early event=%+v writes=%+v", ev, writes)
	}
	if ev := r.Pump(now.Add(2*time.Second), writer); ev.Kind != EventDone {
		t.Fatalf("event=%+v", ev)
	}
	if !reflect.DeepEqual(writes, []write{{"pw\r", true}}) {
		t.Fatalf("writes=%+v", writes)
	}
}

func TestSensitiveAnswerTypedAfterDelaySendsAtOnce(t *testing.T) {
	now := time.Unix(1, 0)
	r := NewConfig(Config{Enabled: true, Steps: []Step{
		{Expect: "Password: ", Sensitive: true, AppendEnter: true, Delay: time.Second},
	}})
	var writes []string
	r.Feed([]byte("Password: "))
	if ev := r.Pump(now, func([]byte, bool) bool { return true }); ev.Kind != EventSecret {
		t.Fatalf("event=%+v", ev)
	}
	// The user took longer than the delay: the answer goes out immediately.
	ev := r.ProvideSecret("pw", now.Add(5*time.Second), func(p []byte, _ bool) bool {
		writes = append(writes, string(p))
		return true
	})
	if ev.Kind != EventDone || !reflect.DeepEqual(writes, []string{"pw\r"}) {
		t.Fatalf("event=%+v writes=%q", ev, writes)
	}
}

func TestNormalizeClampsDelay(t *testing.T) {
	cfg := Normalize(Config{Enabled: true, Steps: []Step{
		{Expect: "a", Delay: -time.Second},
		{Expect: "b", Delay: MaxDelay + time.Hour},
	}})
	if cfg.Steps[0].Delay != 0 {
		t.Fatalf("negative delay survived: %v", cfg.Steps[0].Delay)
	}
	if cfg.Steps[1].Delay != MaxDelay {
		t.Fatalf("long delay=%v want %v", cfg.Steps[1].Delay, MaxDelay)
	}
}

func TestDelayMillisecondConversionClampsOverflow(t *testing.T) {
	if DelayFromMilliseconds(-5) != 0 {
		t.Fatal("negative milliseconds became a delay")
	}
	if got := DelayFromMilliseconds(int(^uint(0) >> 1)); got != MaxDelay {
		t.Fatalf("overflowing milliseconds=%v want %v", got, MaxDelay)
	}
	if got := DelayMilliseconds(MaxDelay + time.Hour); got != MaxDelayMilliseconds {
		t.Fatalf("long duration=%d want %d", got, MaxDelayMilliseconds)
	}
	if got := DelayMilliseconds(-time.Second); got != 0 {
		t.Fatalf("negative duration=%d", got)
	}
}

// assertRunnerForgotEverything checks the per-rule state a finished run must not
// keep, especially a staged sensitive answer.
func assertRunnerForgotEverything(t *testing.T, r *Runner) {
	t.Helper()
	if r.staged || r.stagedValue != "" {
		t.Fatalf("staged secret survived: staged=%v value=%q", r.staged, r.stagedValue)
	}
	if r.awaiting || r.prompt != "" {
		t.Fatalf("open question survived: awaiting=%v prompt=%q", r.awaiting, r.prompt)
	}
	if r.buffer != nil || !r.deadline.IsZero() || !r.delayDeadline.IsZero() || r.matched || !r.matchedAt.IsZero() {
		t.Fatalf("timing state survived: buffer=%q deadline=%v delay=%v matched=%v at=%v",
			r.buffer, r.deadline, r.delayDeadline, r.matched, r.matchedAt)
	}
}

func TestSensitiveWriteFailureAfterDelayClearsStagedSecret(t *testing.T) {
	now := time.Unix(1, 0)
	r := NewConfig(Config{Enabled: true, Steps: []Step{
		{Expect: "Password: ", Sensitive: true, AppendEnter: true, Delay: time.Second},
	}})
	r.Feed([]byte("Password: "))
	if ev := r.Pump(now, func([]byte, bool) bool {
		t.Fatal("nothing may be written before the answer")
		return true
	}); ev.Kind != EventSecret {
		t.Fatalf("event=%+v", ev)
	}
	// The answer is staged while the delay runs.
	if ev := r.ProvideSecret("s3cret", now.Add(200*time.Millisecond), func([]byte, bool) bool {
		t.Fatal("the answer was written before the delay elapsed")
		return true
	}); ev.Kind != EventWait {
		t.Fatalf("event=%+v", ev)
	}
	if !r.staged || r.stagedValue != "s3cret" {
		t.Fatalf("the answer was not staged: %v %q", r.staged, r.stagedValue)
	}

	// The delayed write is refused.
	ev := r.Pump(now.Add(time.Second), func(p []byte, sensitive bool) bool {
		if string(p) != "s3cret\r" || !sensitive {
			t.Fatalf("write=%q sensitive=%v", p, sensitive)
		}
		return false
	})
	if ev.Kind != EventFailed || ev.Step != 0 || !errors.Is(ev.Err, ErrWrite) {
		t.Fatalf("event=%+v", ev)
	}
	if !errors.Is(r.Failed(), ErrWrite) {
		t.Fatalf("failed=%v", r.Failed())
	}
	assertRunnerForgotEverything(t, r)

	// A later frame must not resend the secret.
	if ev := r.Pump(now.Add(2*time.Second), func([]byte, bool) bool {
		t.Fatal("a failed run sent the secret again")
		return true
	}); ev.Kind != EventFailed || ev.Step != 0 || !errors.Is(ev.Err, ErrWrite) {
		t.Fatalf("repeat event=%+v", ev)
	}
	// Cancel after the failure keeps the original error and stays clean.
	r.Cancel()
	if !errors.Is(r.Failed(), ErrWrite) {
		t.Fatalf("cancel overwrote the failure: %v", r.Failed())
	}
	assertRunnerForgotEverything(t, r)
}

func TestCancelClearsStagedSensitiveSecret(t *testing.T) {
	now := time.Unix(1, 0)
	r := NewConfig(Config{Enabled: true, Steps: []Step{
		{Expect: "Password: ", Sensitive: true, AppendEnter: true, Delay: 2 * time.Second},
	}})
	r.Feed([]byte("Password: "))
	if ev := r.Pump(now, func([]byte, bool) bool { return true }); ev.Kind != EventSecret {
		t.Fatalf("event=%+v", ev)
	}
	if ev := r.ProvideSecret("s3cret", now.Add(10*time.Millisecond), func([]byte, bool) bool {
		t.Fatal("wrote before the delay elapsed")
		return true
	}); ev.Kind != EventWait {
		t.Fatalf("event=%+v", ev)
	}
	if !r.staged {
		t.Fatal("answer was not staged before cancel")
	}

	r.Cancel()
	if !errors.Is(r.Failed(), ErrCanceled) {
		t.Fatalf("failed=%v", r.Failed())
	}
	assertRunnerForgotEverything(t, r)

	// Nothing may be written on a later frame.
	if ev := r.Pump(now.Add(3*time.Second), func([]byte, bool) bool {
		t.Fatal("a cancelled delay sent the secret")
		return true
	}); ev.Kind != EventFailed || !errors.Is(ev.Err, ErrCanceled) {
		t.Fatalf("event=%+v", ev)
	}
}

// TestReplyWithColonsIsSentAsOneExactPayload pins the rule that a colon in a
// reply is data, not a field separator: leading, embedded and repeated colons,
// a colon-only answer and a sensitive answer all reach the writer whole.
func TestReplyWithColonsIsSentAsOneExactPayload(t *testing.T) {
	now := time.Unix(1, 0)
	for _, test := range []struct {
		name      string
		step      Step
		answer    string
		want      string
		sensitive bool
	}{
		{"embedded", Step{Send: "user:pass"}, "", "user:pass", false},
		{"leading", Step{Send: ":pass"}, "", ":pass", false},
		{"trailing", Step{Send: "pass:"}, "", "pass:", false},
		{"repeated", Step{Send: "a:b:c:d", AppendEnter: true}, "", "a:b:c:d\r", false},
		{"colon only", Step{Send: ":", AppendEnter: true}, "", ":\r", false},
		{"escaped colon", Step{Send: `a\x3ab`, AppendEnter: true}, "", "a:b\r", false},
		{"sensitive", Step{Expect: "Password:", Sensitive: true, AppendEnter: true}, "user:pass", "user:pass\r", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var got string
			write := func(p []byte, sensitive bool) bool {
				got = string(p)
				if sensitive != test.sensitive {
					t.Fatalf("sensitive=%v want %v", sensitive, test.sensitive)
				}
				return true
			}
			r := NewConfig(Config{Enabled: true, Steps: []Step{test.step}})
			if test.step.Sensitive {
				r.Feed([]byte(test.step.Expect))
				if ev := r.Pump(now, write); ev.Kind != EventSecret {
					t.Fatalf("event=%+v", ev)
				}
				if ev := r.ProvideSecret(test.answer, now, write); ev.Kind != EventDone {
					t.Fatalf("event=%+v", ev)
				}
			} else {
				if ev := r.Pump(now, write); ev.Kind != EventDone {
					t.Fatalf("event=%+v", ev)
				}
			}
			if got != test.want {
				t.Fatalf("reply=%q want %q", got, test.want)
			}
		})
	}
}

// TestCommandModeTypesTheColonAsItsOwnKeystroke pins the TUI path: a rule
// marked CommandMode writes a bare ":" first, waits CommandModePause, and only
// then types its reply. Sending the reply straight away would let a menu shell
// (UsmShell) take its first ":" as the command-line switch and cut the rest.
func TestCommandModeTypesTheColonAsItsOwnKeystroke(t *testing.T) {
	now := time.Unix(1, 0)
	var sent []string
	write := func(p []byte, sensitive bool) bool {
		sent = append(sent, string(p))
		return true
	}
	r := New([]Step{{
		Expect: "[usmshell]$ ", Send: `open -u "1083" -t "ssh:ns@10.200.68.52:22"`,
		AppendEnter: true, CommandMode: true, Timeout: time.Second,
	}})
	r.Feed([]byte("welcome\r\n[usmshell]$ "))
	if ev := r.Pump(now, write); ev.Kind != EventWait {
		t.Fatalf("event=%+v", ev)
	}
	if !reflect.DeepEqual(sent, []string{":"}) {
		t.Fatalf("prefix sent=%q", sent)
	}
	if r.CommandDeadline().IsZero() {
		t.Fatal("no command deadline while waiting to type the reply")
	}
	// Before the pause elapses nothing more is written.
	if ev := r.Pump(now.Add(CommandModePause/2), write); ev.Kind != EventWait {
		t.Fatalf("event=%+v", ev)
	}
	if !reflect.DeepEqual(sent, []string{":"}) {
		t.Fatalf("sent before the pause ended=%q", sent)
	}
	// At the deadline the whole reply (colons included) goes in one write.
	if ev := r.Pump(now.Add(CommandModePause), write); ev.Kind != EventDone {
		t.Fatalf("event=%+v", ev)
	}
	want := []string{":", "open -u \"1083\" -t \"ssh:ns@10.200.68.52:22\"\r"}
	if !reflect.DeepEqual(sent, want) {
		t.Fatalf("sent=%q want %q", sent, want)
	}
}

// TestCommandModeUsesTheRulesDelayAsThePauseAfterTheColon checks that a rule's
// Delay tunes the wait between the ":" and the reply, so a slow menu shell can
// be given longer than the default.
func TestCommandModeUsesTheRulesDelayAsThePauseAfterTheColon(t *testing.T) {
	now := time.Unix(1, 0)
	var sent []string
	write := func(p []byte, sensitive bool) bool {
		sent = append(sent, string(p))
		return true
	}
	r := New([]Step{{
		Expect: "ready", Send: "go", AppendEnter: true,
		Delay: time.Second, CommandMode: true, Timeout: 5 * time.Second,
	}})
	r.Feed([]byte("ready"))
	// The ":" is typed as soon as the prompt matches; the Delay is the pause
	// before the reply, not before the ":".
	if ev := r.Pump(now, write); ev.Kind != EventWait {
		t.Fatalf("event=%+v", ev)
	}
	if !reflect.DeepEqual(sent, []string{":"}) {
		t.Fatalf("sent=%q", sent)
	}
	if ev := r.Pump(now.Add(time.Second/2), write); ev.Kind != EventWait {
		t.Fatalf("event=%+v", ev)
	}
	if !reflect.DeepEqual(sent, []string{":"}) {
		t.Fatalf("replied before the rule's delay elapsed: %q", sent)
	}
	if ev := r.Pump(now.Add(time.Second), write); ev.Kind != EventDone {
		t.Fatalf("event=%+v", ev)
	}
	if want := []string{":", "go\r"}; !reflect.DeepEqual(sent, want) {
		t.Fatalf("sent=%q want %q", sent, want)
	}
}
