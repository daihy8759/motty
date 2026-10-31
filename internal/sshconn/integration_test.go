package sshconn

import (
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const ubuntuBanner = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"

func TestIntegrationExecCancellationWhileAcknowledgmentIsWithheld(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	server := startServer(t, func(server *testServer) {
		server.version = ubuntuBanner
		server.password, server.shell = "secret", echoShell
		server.beforeExecReply = func(string) {
			close(started)
			<-release
		}
		server.command = func(_ string, channel ssh.Channel) {
			defer channel.Close()
			channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		}
	})
	defer close(release)
	h := connect(t, server)
	result := make(chan error, 1)
	go func() {
		_, err := h.conn.OpenShell(ShellConfig{Cols: 80, Rows: 24, IntegrateShell: true})
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the integration wrapper never reached the exec request")
	}
	h.conn.Cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceling while the exec acknowledgment was withheld still opened a shell")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation is waiting for the withheld exec acknowledgment")
	}
}

func TestIntegrationSSHStartupAndFallback(t *testing.T) {
	for _, mode := range []string{"integrated", "unknown-banner", "exec-refused", "custom-command"} {
		t.Run(mode, func(t *testing.T) {
			server := startServer(t, func(server *testServer) {
				server.password, server.shell = "secret", echoShell
				if mode != "unknown-banner" {
					server.version = ubuntuBanner
				}
				server.command = func(command string, channel ssh.Channel) {
					defer channel.Close()
					text := "integrated-startup"
					if mode == "custom-command" {
						if command != "custom shell" {
							t.Errorf("custom command replaced by %q", command)
						}
						text = "custom-startup"
					} else if !strings.Contains(command, "motty-shell") {
						t.Errorf("integration wrapper missing from %q", command)
					}
					io.WriteString(channel, text)
					channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				}
				server.refuseCommand = func(command string) bool {
					return mode == "exec-refused" && strings.Contains(command, "motty-shell")
				}
			})
			h := connect(t, server)
			config := ShellConfig{Cols: 80, Rows: 24, IntegrateShell: true}
			want := "integrated-startup"
			switch mode {
			case "custom-command":
				config.Command, want = "custom shell", "custom-startup"
			case "unknown-banner", "exec-refused":
				want = "welcome"
			}
			w := openShellWith(t, h, config)
			w.until(want, func(output string) bool { return strings.Contains(output, want) })
		})
	}
}

// TestIntegrationWrapperIsOneChannel proves the discovery that used to be a
// second session is now baked into the shell command itself, so an unsupported
// shell still starts plainly without Motty opening anything extra.
func TestIntegrationWrapperIsOneChannel(t *testing.T) {
	if got := integrationWrapperCommand("pty-token"); got == "" {
		t.Fatal("a valid token should build the wrapper")
	} else if !strings.Contains(got, "bash") || !strings.Contains(got, "zsh") {
		t.Fatalf("wrapper does not select both shells: %q", got)
	}
	for _, token := range []string{"bad token", "bad;rm", strings.Repeat("x", 129)} {
		if got := integrationWrapperCommand(token); got != "" {
			t.Errorf("invalid token %q enabled integration", token)
		}
	}
	if integrationWrapperCommand() == "" {
		t.Fatal("the wrapper should still work without a token")
	}
}

func TestShellProbeSafetyIsAPositiveAllowList(t *testing.T) {
	for _, banner := range []string{ubuntuBanner, "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"} {
		if !shellProbeSafe(banner) {
			t.Errorf("shellProbeSafe(%q) = false, want true", banner)
		}
	}
	for _, banner := range []string{
		"", "SSH-2.0-OpenSSH_9.7", "SSH-2.0-HUAWEI-1.5", "SSH-2.0-GopTest",
	} {
		if shellProbeSafe(banner) {
			t.Errorf("shellProbeSafe(%q) = true, want false for an unidentified host", banner)
		}
	}
	// The exported policy the workbench uses for automatic file sessions and
	// connection sharing is exactly this allow-list.
	if !SafeForAuxiliaryChannels(ubuntuBanner) {
		t.Error("an identified host should permit auxiliary channels")
	}
	if SafeForAuxiliaryChannels("SSH-2.0-OpenSSH_9.7") {
		t.Error("an unidentified host must not permit auxiliary channels")
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
