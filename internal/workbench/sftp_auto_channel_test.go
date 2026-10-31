package workbench

import (
	"os"
	"testing"
	"time"

	"motty/internal/sshconn"
	layoutcore "motty/internal/workspace"
)

// autoPanelState connects a saved host with the file panel set to open
// automatically. extra says whether the connection permits a second channel
// (a positively identified host) or not (a single-session/unknown appliance).
func autoPanelState(t *testing.T, extra bool, banner string) (*State, *fakeConn, *Session) {
	t.Helper()
	world, options := newWorld(t)
	options.Invalidate = func() {}
	state := newTestState(t, options)
	state.sftpPanelAutoOpen = true
	fake := connect(t, state, world)
	remote := &workbenchSFTPRemote{
		cwd:     "/home/test",
		entries: map[string][]os.FileInfo{"/home/test": nil},
		files:   map[string][]byte{},
	}
	fake.mu.Lock()
	fake.extraChannels = &extra
	fake.sftp = remote
	fake.mu.Unlock()
	fake.set(func(status *sshconn.Status) {
		status.Phase = sshconn.PhaseConnected
		status.ServerVersion = banner
		status.Method = "password"
	})
	state.Wake()
	session, ok := state.sessionByIDPointer(state.activeSessionID)
	if !ok {
		t.Fatal("no active session after connecting")
	}
	return state, fake, session
}

func (fake *fakeConn) sftpOpenCount() int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.sftpOpens
}

// assertNoAutomaticSFTP waits long enough for any worker to run, then insists
// the automatic path opened nothing.
func assertNoAutomaticSFTP(t *testing.T, state *State, session *Session, fake *fakeConn) {
	t.Helper()
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		state.Wake()
		time.Sleep(5 * time.Millisecond)
	}
	if session.files != nil {
		t.Fatal("the file panel opened automatically on a host that allows only one session")
	}
	if opens := fake.sftpOpenCount(); opens != 0 {
		t.Fatalf("OpenSFTP ran %d times automatically on a single-session host", opens)
	}
}

func waitSFTPSession(t *testing.T, state *State, session *Session, fake *fakeConn) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state.Wake()
		if session.files != nil && fake.sftpOpenCount() > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if session.files == nil {
		t.Fatal("the file panel never started")
	}
	t.Fatalf("OpenSFTP ran %d times, want at least one", fake.sftpOpenCount())
}

// TestAutomaticFilePanelOpensForAnIdentifiedHost is the regression cover for
// ordinary servers: when the connection positively permits an extra channel,
// the auto-open panel still starts its SFTP session.
func TestAutomaticFilePanelOpensForAnIdentifiedHost(t *testing.T) {
	state, fake, session := autoPanelState(t, true, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
	if session.term == nil || session.term.shell == nil {
		t.Fatal("the shell did not open before the file panel")
	}
	waitSFTPSession(t, state, session, fake)
}

// TestAutomaticFilePanelSkipsTheSecondChannelOnAnUnidentifiedHost is the
// regression for the reported failure timing: the panel is configured to open
// automatically and the shell is up, but the connection may be a single-session
// appliance, so Motty must not open an SFTP session on that transport. The
// empty panel still offers Open, and that explicit choice does open it.
func TestAutomaticFilePanelSkipsTheSecondChannelOnAnUnidentifiedHost(t *testing.T) {
	state, fake, session := autoPanelState(t, false, "SSH-2.0-OpenSSH_9.6")
	if session.term == nil || session.term.shell == nil {
		t.Fatal("the shell did not open")
	}
	assertNoAutomaticSFTP(t, state, session, fake)

	// The panel is up but empty; its Open button is the explicit path.
	context, _ := state.deck.Context(state.deck.ActiveWorkspace())
	if !context.Open || context.Kind != layoutcore.ContextSFTP {
		t.Fatalf("the file panel is not open: %+v", context)
	}

	// The user's explicit choice is still honoured.
	state.Click(hitSFTPOpen)
	if session.files == nil {
		t.Fatal("an explicit Open did not start the file panel")
	}
	waitSFTPSession(t, state, session, fake)
}

// TestUnidentifiedHostIsNotSharedIntoAnotherTab proves the same gate covers
// connection sharing, which would otherwise put a second shell channel on the
// single-session transport. The second tab dials its own connection instead.
func TestUnidentifiedHostIsNotSharedIntoAnotherTab(t *testing.T) {
	sharing, options := newSharingWorld(t)
	options.Invalidate = func() {}
	state := newTestState(t, options)
	first := sharing.connectFirst(t, state)
	no := false
	first.mu.Lock()
	first.extraChannels = &no
	first.mu.Unlock()

	state.newHostSession(state.hosts[0])
	if len(sharing.conns) != 2 {
		t.Fatalf("connections dialed = %d, want a fresh one for the second tab", len(sharing.conns))
	}
	if len(sharing.shared) != 0 {
		t.Fatalf("the single-session transport was shared %d times", len(sharing.shared))
	}
}
