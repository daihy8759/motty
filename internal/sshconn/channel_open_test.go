package sshconn

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestShellIsTheFirstChannelOnAnUnidentifiedSingleSessionServer reproduces the
// field timing: a server that tears the transport down as soon as a second
// session is opened, and whose banner matches no vendor or OS. Before the fix
// the automatic system probe (and, under other banners, the integration probe)
// opened that first session, so the user's shell became the fatal second one.
// Now the shell is the only channel and starts on the first try.
func TestShellIsTheFirstChannelOnAnUnidentifiedSingleSessionServer(t *testing.T) {
	server := startServer(t, func(server *testServer) {
		// "GopTest" identifies nothing, exactly like a device with a generic
		// OpenSSH banner: it must not be probed.
		server.password, server.shell = "secret", echoShell
		server.exec = func(string) (string, uint32) { return "kernel=Linux\nid=ubuntu\n", 0 }
		server.command = func(string, ssh.Channel) {}
		server.onSessionOpen = func(index int) bool { return index > 1 }
	})
	h := connect(t, server)
	shell, err := h.conn.OpenShell(ShellConfig{Cols: 80, Rows: 24, IntegrateShell: true})
	if err != nil {
		t.Fatalf("OpenShell: %v", err)
	}
	defer shell.Close()

	deadline := time.Now().Add(5 * time.Second)
	for server.sessionOpens() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("session channels opened = %d, want exactly the shell", server.sessionOpens())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Give an accidental background session a chance to appear and be counted.
	time.Sleep(150 * time.Millisecond)
	if got := server.sessionOpens(); got != 1 {
		t.Fatalf("session channels opened = %d, want exactly the shell", got)
	}
}

// TestChannelOpenAfterPeerDropsTransportIsAConnectionLoss pins the real meaning
// of x/crypto/ssh's "unexpected packet in response to channel open: <nil>": the
// mux loop exited while the open was pending, so the library read a nil message
// from a closed channel. It is a gone transport, not a packet from the server,
// and must never be treated as a live connection to reuse.
func TestChannelOpenAfterPeerDropsTransportIsAConnectionLoss(t *testing.T) {
	server := startServer(t, func(server *testServer) {
		server.password, server.shell = "secret", echoShell
		// Drop the transport the instant the first session channel arrives,
		// without confirming or rejecting it.
		server.onSessionOpen = func(int) bool { return true }
	})
	h := connect(t, server)

	_, err := h.conn.OpenShell(ShellConfig{Cols: 80, Rows: 24})
	if err == nil {
		t.Fatal("OpenShell succeeded although the peer dropped the transport")
	}
	if !errors.Is(err, ErrTransportClosed) {
		t.Fatalf("OpenShell error = %v, want ErrTransportClosed", err)
	}
	if !errors.Is(err, ErrDisconnected) {
		t.Fatalf("OpenShell error lost ErrDisconnected: %v", err)
	}
	if errors.Is(err, ErrMalformedDisconnect) {
		t.Fatalf("a closed mux was mistaken for a malformed disconnect: %v", err)
	}
	if !strings.Contains(err.Error(), "channel could be opened") {
		t.Fatalf("the error does not explain the lost transport: %v", err)
	}

	select {
	case <-h.conn.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the connection did not finish after the transport was dropped")
	}
	if status := h.conn.Status(); status.Phase != PhaseClosed || !errors.Is(status.Err, ErrDisconnected) {
		t.Fatalf("final status = %+v, want closed/disconnected", status)
	}
}

func TestNormalizeChannelOpenNilIsATransportClose(t *testing.T) {
	raw := errors.New("ssh: unexpected packet in response to channel open: <nil>")
	err := normalizeServerError(raw)
	if !errors.Is(err, ErrTransportClosed) || !errors.Is(err, ErrDisconnected) {
		t.Fatalf("normalizeServerError(%v) = %v, want ErrTransportClosed and ErrDisconnected", raw, err)
	}
	if errors.Is(err, ErrMalformedDisconnect) {
		t.Fatalf("a nil channel-open was classified as a malformed disconnect: %v", err)
	}
	if unwrapped := errors.Unwrap(err); unwrapped == nil || unwrapped.Error() != raw.Error() {
		t.Fatalf("the library error is no longer reachable: %v", errors.Unwrap(err))
	}
	if again := normalizeServerError(err); again != err {
		t.Fatalf("normalization is not idempotent: %v != %v", again, err)
	}
	for _, candidate := range []error{raw, err} {
		if !transportGone(candidate) {
			t.Errorf("transportGone(%v) = false, want true", candidate)
		}
	}
}

// TestSystemProbeTransportFailureIsNotSwallowed covers the opt-in probe: a
// transport that dies during it must fail the connection with a disconnect, not
// be swallowed and leave Motty opening the shell on a dead client.
func TestSystemProbeTransportFailureIsNotSwallowed(t *testing.T) {
	server := startServer(t, func(server *testServer) {
		server.version = ubuntuBanner
		server.password = "secret"
		server.exec = func(string) (string, uint32) { return "", 0 }
		server.killOnExec = true
	})
	h := dial(t, server, func(config *Config) { config.DetectSystem = true })
	h.phase(PhaseHostKeyPrompt)
	h.conn.TrustHostKey(false)
	h.phase(PhasePasswordPrompt)
	h.conn.SubmitPassword("secret")

	status := h.until("probe transport loss", func(status Status) bool {
		return status.Phase == PhaseClosed || status.Phase == PhaseFailed
	})
	if status.Err == nil || !errors.Is(status.Err, ErrDisconnected) {
		t.Fatalf("status after a probe loss = %+v, want a disconnect cause", status)
	}
	if _, err := h.conn.RunCommand(context.Background(), "true", 16); err == nil {
		t.Fatal("a command still ran on the dead transport")
	}
}
