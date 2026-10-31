package workbench

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/vivaui/viva/app"
	"github.com/vivaui/viva/ui"
)

// newTestState is New for a test that may open the assistant's database: the
// state is closed when the test ends, because Windows cannot delete an open file.
func newTestState(t testing.TB, options Options) *State {
	t.Helper()
	if options.KnownHostsPath == "" {
		// Left empty, it and an empty StatePath default to the user's own Motty
		// folder: a test would open the real config.db and stamp it with this
		// build's format.
		options.KnownHostsPath = filepath.Join(t.TempDir(), "known_hosts")
	}
	if options.PreferredLanguages == nil {
		// The tests read English; the machine running them may not speak it.
		options.PreferredLanguages = func() []string { return nil }
	}
	if options.SystemAppearance == nil {
		// So are the tests' looks: the machine running them may be light.
		options.SystemAppearance = func() app.Appearance { return app.AppearanceUnknown }
	}
	if options.SetNativeAppearance == nil {
		options.SetNativeAppearance = func(app.Appearance) {}
	}
	if options.WatchSystemAppearance == nil {
		options.WatchSystemAppearance = func(func()) func() { return func() {} }
	}
	state := New(options)
	// A test never waits for the automatic check; the ones that exercise it set
	// these back to something short.
	state.update.firstDelay, state.update.every = time.Hour, time.Hour
	t.Cleanup(state.Close)
	return state
}

// eventCanvases keeps, per state, the canvas the pointer helper paints events into.
// A real window has one; a test that calls state.Pointer directly has none, so the
// helper makes it. It lives in the test, not in State: production code never holds
// a canvas.
var eventCanvases = map[*State]*ui.Canvas{}

// pointer sends a pointer event the way a window does: to the state's Pointer
// first and, if nothing there took it, to the controls that declared themselves
// to it while painting (the event pass). The state is painted once before its first
// event so that the controls have declared what they listen to.
func pointer(state *State, event ui.PointerEvent) ui.EventResult {
	if event.Viewport == (ui.Size{}) {
		event.Viewport = ui.Size{Width: 1400, Height: 900}
	}
	canvas, seen := eventCanvases[state]
	if !seen {
		canvas = &ui.Canvas{}
		eventCanvases[state] = canvas
		canvas.BeginFrame()
		state.Paint(canvas, event.Viewport)
		canvas.EndFrame()
	}
	result := state.Pointer(event)
	if result.Handled {
		return result
	}
	if canvas.DeliverPointer(event, event.Viewport, state.Paint) {
		result.Handled, result.Repaint = true, true
	}
	return result
}
