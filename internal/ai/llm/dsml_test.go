package llm

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// The V4.1 "calls" dialect, the shape issue #225 shows.
const dsmlCalls = "<｜DSML｜ calls>\n" +
	"<｜DSML｜ invoke name=\"terminal_exec\">\n" +
	"<｜DSML｜ parameter name=\"command\" string=\"true\">uptime</｜DSML｜ parameter>\n" +
	"<｜DSML｜ parameter name=\"timeout_seconds\" string=\"false\">30</｜DSML｜ parameter>\n" +
	"</｜DSML｜ invoke>\n" +
	"</｜DSML｜ calls>"

var dsmlWant = []ToolCall{{Name: "terminal_exec", Arguments: `{"command":"uptime","timeout_seconds":30}`}}

// feedDSML pushes chunks through a filter and returns what it published.
func feedDSML(t *testing.T, enabled bool, chunks ...string) (string, []ToolCall, error) {
	t.Helper()
	f := newDSMLFilter(enabled)
	var (
		b     strings.Builder
		calls []ToolCall
	)
	for _, chunk := range chunks {
		text, got, err := f.push(chunk)
		if err != nil {
			return "", nil, err
		}
		b.WriteString(text)
		calls = append(calls, got...)
	}
	text, got, err := f.flush()
	b.WriteString(text)
	calls = append(calls, got...)
	return b.String(), calls, err
}

func TestDSMLRecoversEveryDialect(t *testing.T) {
	cases := []struct {
		name   string
		markup string
		want   []ToolCall
	}{
		{"v41-calls", dsmlCalls, dsmlWant},
		{"v32-function_calls", strings.ReplaceAll(dsmlCalls, "calls>", "function_calls>"), dsmlWant},
		{"v4-tool_calls", strings.ReplaceAll(dsmlCalls, "calls>", "tool_calls>"), dsmlWant},
		{"ascii-bars", strings.ReplaceAll(dsmlCalls, "｜", "|"), dsmlWant},
		{"doubled-bars", strings.ReplaceAll(dsmlCalls, "｜", "||"), dsmlWant},
		{"spaced-bars", strings.ReplaceAll(dsmlCalls, "｜", " | "), dsmlWant},
		{"no-wrapper", "<｜DSML｜ invoke name=\"terminal_exec\">" +
			"<｜DSML｜ parameter name=\"command\" string=\"true\">uptime</｜DSML｜ parameter>" +
			"<｜DSML｜ parameter name=\"timeout_seconds\" string=\"false\">30</｜DSML｜ parameter>" +
			"</｜DSML｜ invoke>", dsmlWant},
		{"bare-json", "<｜DSML｜ calls><｜DSML｜ invoke name=\"terminal_exec\">" +
			`{"command":"uptime"}</｜DSML｜ invoke></｜DSML｜ calls>`,
			[]ToolCall{{Name: "terminal_exec", Arguments: `{"command":"uptime"}`}}},
		{"truncated-block", "<｜DSML｜ calls>\n<｜DSML｜ invoke name=\"terminal_exec\">\n" +
			"<｜DSML｜ parameter name=\"command\" string=\"true\">uptime</｜DSML｜ parameter>\n" +
			"<｜DSML｜ parameter name=\"timeout_seconds\" string=\"false\">30</｜DSML｜ parameter>\n" +
			"</｜DSML｜ invoke>\n", dsmlWant},
		{"prose-around", "Running it.\n" + dsmlCalls + "\nThen I will read the output.", dsmlWant},
		{"stray-tags", "<｜DSML｜ caller>hello</｜DSML｜ caller>", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			text, calls, err := feedDSML(t, true, c.markup)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(calls, c.want) {
				t.Fatalf("calls = %#v, want %#v", calls, c.want)
			}
			if strings.Contains(text, "DSML") {
				t.Fatalf("markup reached the text channel: %q", text)
			}
			if c.name == "prose-around" && (!strings.HasPrefix(text, "Running it.") || !strings.Contains(text, "Then I will read")) {
				t.Fatalf("prose lost: %q", text)
			}
			if c.name == "stray-tags" && text != "hello" {
				t.Fatalf("text = %q, want %q", text, "hello")
			}
		})
	}
}

// A delta boundary can fall anywhere, including inside a bar or an opener.
func TestDSMLRecoversAcrossAnyDeltaBoundary(t *testing.T) {
	wantText, wantCalls, err := feedDSML(t, true, dsmlCalls)
	if err != nil {
		t.Fatal(err)
	}
	for cut := 1; cut < len(dsmlCalls); cut++ {
		text, calls, err := feedDSML(t, true, dsmlCalls[:cut], dsmlCalls[cut:])
		if err != nil {
			t.Fatalf("cut %d: %v", cut, err)
		}
		if !reflect.DeepEqual(calls, wantCalls) || text != wantText {
			t.Fatalf("cut %d: text %q calls %#v", cut, text, calls)
		}
	}
	var chunks []string
	for _, r := range dsmlCalls {
		chunks = append(chunks, string(r))
	}
	text, calls, err := feedDSML(t, true, chunks...)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, wantCalls) || text != wantText {
		t.Fatalf("bytewise: text %q calls %#v", text, calls)
	}
}

func TestDSMLPassesOrdinaryTextThrough(t *testing.T) {
	for _, text := range []string{
		"",
		"No markup here.",
		"a < b and c > d",
		"use <div> or <|> as separators",
		strings.Repeat("x", 4096),
	} {
		got, calls, err := feedDSML(t, true, text)
		if err != nil || got != text || calls != nil {
			t.Fatalf("%q: got %q %#v %v", text, got, calls, err)
		}
	}
	// The same text split at every boundary must survive too.
	long := "if a < b then print(a < b); no tag follows this prefix <"
	for cut := 0; cut <= len(long); cut++ {
		got, _, err := feedDSML(t, true, long[:cut], long[cut:])
		if err != nil || got != long {
			t.Fatalf("cut %d: got %q err %v", cut, got, err)
		}
	}
}

func TestDSMLMarkupThatYieldsNoCallIsAnError(t *testing.T) {
	_, _, err := feedDSML(t, true, "<｜DSML｜ calls>\n<｜DSML｜ invoke name=\"x\">\n</｜DSML｜ calls>")
	if err == nil {
		t.Fatal("an unrecoverable block passed as an answer")
	}
}

func TestDSMLIsIgnoredWithoutTools(t *testing.T) {
	got, calls, err := feedDSML(t, false, dsmlCalls)
	if err != nil || calls != nil || got != dsmlCalls {
		t.Fatalf("disabled filter changed the stream: %q %#v %v", got, calls, err)
	}
}

func TestDSMLThroughTheChatStream(t *testing.T) {
	body := oaText("Let me check.\n"+dsmlCalls+"\n") + oaFinish("stop")
	srv := sseServer(t, body, true, nil)
	req := Request{Model: "m", Messages: []Message{{Role: RoleUser, Text: "check"}},
		Tools: []ToolSpec{{Name: "terminal_exec"}}}
	ch, err := NewOpenAI(Config{BaseURL: srv.URL, APIKey: testKey}).Stream(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	evs := collect(t, ch)
	stop := terminal(t, evs)
	if stop.Kind != EventDone {
		t.Fatalf("stream ended with %+v", stop)
	}
	if got := toolCalls(evs); !reflect.DeepEqual(got, dsmlWant) {
		t.Fatalf("calls = %#v", got)
	}
	if got := text(evs, EventText); strings.Contains(got, "DSML") || !strings.Contains(got, "Let me check.") {
		t.Fatalf("text = %q", got)
	}
	if stop.StopReason != "tool_calls" {
		t.Fatalf("stop reason = %q, want the recovered call to have upgraded it", stop.StopReason)
	}
}

func TestDSMLWithoutToolsKeepsTheText(t *testing.T) {
	body := oaText(dsmlCalls) + oaFinish("stop")
	srv := sseServer(t, body, false, nil)
	ch, err := NewOpenAI(Config{BaseURL: srv.URL, APIKey: testKey}).Stream(bg, simpleReq)
	if err != nil {
		t.Fatal(err)
	}
	evs := collect(t, ch)
	terminal(t, evs)
	if toolCalls(evs) != nil || !strings.Contains(text(evs, EventText), "DSML") {
		t.Fatalf("a request without tools must not recover calls: %+v", evs)
	}
}

func TestDSMLThroughTheResponsesStream(t *testing.T) {
	body := rsText("Let me check.\n", dsmlCalls, "\n") + rsCompleted()
	srv := sseServer(t, body, true, nil)
	req := Request{Model: "m", Messages: []Message{{Role: RoleUser, Text: "check"}},
		Tools: []ToolSpec{{Name: "terminal_exec"}}}
	ch, err := NewOpenAIResponses(Config{BaseURL: srv.URL, APIKey: testKey}).Stream(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	evs := collect(t, ch)
	stop := terminal(t, evs)
	if got := toolCalls(evs); !reflect.DeepEqual(got, dsmlWant) {
		t.Fatalf("calls = %#v", got)
	}
	if got := text(evs, EventText); strings.Contains(got, "DSML") || !strings.Contains(got, "Let me check.") {
		t.Fatalf("text = %q", got)
	}
	if stop.StopReason != "tool_calls" {
		t.Fatalf("stop reason = %q", stop.StopReason)
	}
}

// The filter sits on every content delta, so the ordinary case must stay free.
func BenchmarkDSMLText(b *testing.B) {
	delta := "The quick brown fox jumps over the lazy dog; nothing here is markup. "
	b.SetBytes(int64(len(delta)))
	b.ReportAllocs()
	f := newDSMLFilter(true)
	for i := 0; i < b.N; i++ {
		if _, _, err := f.push(delta); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDSMLMarkup(b *testing.B) {
	b.SetBytes(int64(len(dsmlCalls)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		f := newDSMLFilter(true)
		if _, _, err := f.push(dsmlCalls); err != nil {
			b.Fatal(err)
		}
		if _, _, err := f.flush(); err != nil {
			b.Fatal(err)
		}
	}
}
