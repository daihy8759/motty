package sshconn

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestIntegrationProbeCancellationWhileExecAcknowledgmentIsWithheld(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	server := startServer(t, func(server *testServer) {
		server.password, server.shell = "secret", echoShell
		server.beforeExecReply = func(command string) {
			if command == shellIntegrationProbe {
				close(started)
				<-release
			}
		}
		server.command = func(_ string, channel ssh.Channel) {
			defer channel.Close()
			channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		}
	})
	defer close(release)
	h := connect(t, server)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := h.conn.RunCommand(ctx, shellIntegrationProbe, 4096)
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("probe never reached exec request")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled establishment returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation is waiting for the withheld exec acknowledgment")
	}
	w := openShell(t, h, 80, 24)
	w.until("normal shell fallback", func(output string) bool { return strings.Contains(output, "welcome") })
}

func TestIntegrationSSHStartupAndFallback(t *testing.T) {
	for _, mode := range []string{"integrated", "probe-refused", "unsupported", "exec-refused", "custom-command"} {
		t.Run(mode, func(t *testing.T) {
			server := startServer(t, func(server *testServer) {
				server.password, server.shell = "secret", echoShell
				server.version = "SSH-2.0-OpenSSH_9.6" // probes run only on known implementations
				server.command = func(command string, channel ssh.Channel) {
					defer channel.Close()
					text := "integrated-startup"
					if command == shellIntegrationProbe {
						text = "\x1emotty-shell:/bin/bash\x1f"
						if mode == "unsupported" {
							text = "\x1emotty-shell:/bin/fish\x1f"
						}
					} else if mode == "custom-command" {
						if command != "custom shell" {
							t.Errorf("custom command replaced by %q", command)
						}
						text = "custom-startup"
					}
					io.WriteString(channel, text)
					channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				}
				server.refuseCommand = func(command string) bool {
					return mode == "probe-refused" && command == shellIntegrationProbe ||
						mode == "exec-refused" && command != shellIntegrationProbe
				}
			})
			h := connect(t, server)
			config := ShellConfig{Cols: 80, Rows: 24, IntegrateShell: true}
			want := "integrated-startup"
			if mode == "custom-command" {
				config.Command, want = "custom shell", "custom-startup"
			} else if mode != "integrated" {
				want = "welcome"
			}
			w := openShellWith(t, h, config)
			w.until(want, func(output string) bool { return strings.Contains(output, want) })
		})
	}
}

func TestWSLIntegrationScriptRefusesWhatCouldBeInjected(t *testing.T) {
	for _, test := range []struct{ token, variable string }{
		{"", "MOTTY_CD"}, {"bad token", "MOTTY_CD"}, {"tok';touch /tmp/no", "MOTTY_CD"}, {strings.Repeat("a", 129), "MOTTY_CD"},
		{"token", ""}, {"token", "lower"}, {"token", "A;touch /tmp/no"}, {"token", "A B"}, {"token", "1A"},
	} {
		if script := WSLIntegrationScript(test.token, test.variable); script != "" {
			t.Errorf("token %q and variable %q were accepted", test.token, test.variable)
		}
	}
	script := WSLIntegrationScript("token-1", "MOTTY_CD")
	if script == "" || strings.Contains(script, "__MOTTY_SUFFIX__") || !strings.Contains(script, ";motty=token-1") {
		t.Fatalf("script = %q", script)
	}
}
