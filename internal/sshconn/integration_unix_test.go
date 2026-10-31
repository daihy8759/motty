//go:build !windows

package sshconn

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
	"motty/internal/localshell"
	"motty/internal/term"
)

func TestIntegrationRealSSHPTYTracksCD(t *testing.T) {
	program, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	home := t.TempDir()
	target := filepath.Join(home, "ssh dir%#")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	server := startServer(t, func(server *testServer) {
		// A recognised OS banner enables the single-channel integration wrapper.
		server.version = ubuntuBanner
		server.password, server.shell = "secret", echoShell
		server.command = func(command string, channel ssh.Channel) {
			defer channel.Close()
			cmd := exec.Command("/bin/sh", "-c", command)
			cmd.Dir = home
			cmd.Env = append(os.Environ(), "HOME="+home, "SHELL="+program)
			master, err := pty.Start(cmd)
			if err != nil {
				t.Errorf("SSH PTY: %v", err)
				return
			}
			defer master.Close()
			inputDone := make(chan struct{})
			go func() {
				io.Copy(master, channel)
				master.Close()
				close(inputDone)
			}()
			io.Copy(channel, master)
			status := uint32(0)
			if err := cmd.Wait(); err != nil {
				status = 1
			}
			channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
			channel.Close()
			<-inputDone
		}
	})
	h := connect(t, server)
	w := openShellWith(t, h, ShellConfig{Cols: 80, Rows: 24, IntegrateShell: true, IntegrationToken: "pty-test-token"})
	screen := term.New(80, 24, 0)
	screen.SetPromptToken("pty-test-token")
	ready, consumed := 0, 0
	screen.SetPromptReady(func() { ready++ })
	parse := func(output string) {
		screen.Write([]byte(output[consumed:]))
		consumed = len(output)
	}
	w.until("integrated SSH prompt", func(output string) bool { parse(output); return ready > 0 })
	w.shell.Write([]byte("cd -- '" + target + "'\r"))
	w.until("SSH cd report", func(output string) bool {
		parse(output)
		cwd, ok := screen.WorkingDirectory()
		return ready > 1 && ok && cwd.Path == target
	})
	w.shell.Write([]byte("exit\r"))
	w.waitDone()
}

func TestIntegrationReportsRealShellDirectoriesWithoutChangingProfiles(t *testing.T) {
	for _, name := range []string{"bash", "zsh"} {
		t.Run(name, func(t *testing.T) {
			program, err := exec.LookPath(name)
			if err != nil {
				t.Skipf("%s unavailable: %v", name, err)
			}
			home, runtimeDir := t.TempDir(), t.TempDir()
			target := filepath.Join(home, "a b%'#;$()", "caf\u00e9")
			if err := os.MkdirAll(target, 0700); err != nil {
				t.Fatal(err)
			}
			profile := "printf 'user-profile-loaded\\n'\n"
			file := ".bash_profile"
			if name == "bash" {
				profile += "PS1='user-prompt> '; PROMPT_COMMAND='printf \"user-hook\\n\"'\n"
			} else {
				file = ".zshrc"
				profile += "PS1='user-prompt> '; precmd() { printf 'user-hook\\n'; }\n"
			}
			profilePath := filepath.Join(home, file)
			if err := os.WriteFile(profilePath, []byte(profile), 0600); err != nil {
				t.Fatal(err)
			}
			shell, err := localshell.Start(localshell.Config{
				Shell: "/bin/sh", Args: []string{"-c", "umask 022; " + integrationCommand(program, "pty-test-token")}, Dir: home,
				Env:  []string{"HOME=" + home, "ZDOTDIR=" + home, "SHELL=" + program, "TMPDIR=" + runtimeDir, "LANG=en_US.UTF-8"},
				Cols: 120, Rows: 24,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(shell.Close)
			screen := term.New(120, 24, 0)
			screen.SetPromptToken("pty-test-token")
			ready, commandStarts, output := 0, 0, ""
			screen.SetPromptReady(func() { ready++ })
			screen.SetCommandStart(func() { commandStarts++ })
			await := func(want string, predicate func() bool) {
				t.Helper()
				deadline := time.Now().Add(8 * time.Second)
				for time.Now().Before(deadline) {
					data := shell.Drain(nil)
					output += string(data)
					screen.Write(data)
					if predicate() {
						return
					}
					time.Sleep(5 * time.Millisecond)
				}
				t.Fatalf("waiting for %s: %q", want, output)
			}
			await("initial ready prompt", func() bool { return ready > 0 })
			version, _ := exec.Command(program, "--version").Output()
			commandReporting := name == "zsh" || strings.Contains(string(version), "version 5.") || strings.Contains(string(version), "version 6.")
			if commandReporting && commandStarts == 0 {
				t.Fatal("supported shell did not announce command-start reporting")
			}
			if !strings.Contains(output, "user-profile-loaded") || !strings.Contains(output, "user-hook") {
				t.Fatalf("profile/hook lost: %q", output)
			}
			shell.Write([]byte(": > \"$HOME/mask-file\"; mkdir \"$HOME/mask-dir\"; printf 'mask-check-done\\n'\r"))
			await("file creation", func() bool { return strings.Contains(output, "mask-check-done\r\n") })
			for name, mode := range map[string]os.FileMode{"mask-file": 0644, "mask-dir": 0755} {
				info, err := os.Stat(filepath.Join(home, name))
				if err != nil || info.Mode().Perm() != mode {
					t.Fatalf("inherited umask changed for %s: info=%v, err=%v; want %04o", name, info, err, mode)
				}
			}
			before, startsBefore := ready, commandStarts
			shell.Write([]byte("cd -- '" + strings.ReplaceAll(target, "'", "'\\''") + "'\r"))
			await("cd report", func() bool {
				cwd, ok := screen.WorkingDirectory()
				return ok && cwd.Path == target && ready > before
			})
			if commandReporting && commandStarts <= startsBefore {
				t.Fatal("an actual cd was not preceded by a command-start marker")
			}
			if strings.Count(output, "user-hook\r\n") < 2 {
				t.Fatalf("hook was overwritten: %q", output)
			}
			if name == "zsh" {
				shell.Write([]byte("printf 'zdot=%s\\n' \"$ZDOTDIR\"\r"))
				await("restored ZDOTDIR", func() bool { return strings.Contains(output, "zdot="+home+"\r\n") })
			}
			shell.Write([]byte("exit 7\r"))
			select {
			case <-shell.Done():
			case <-time.After(8 * time.Second):
				t.Fatal("integrated shell did not exit")
			}
			if shell.ExitStatus() != 7 {
				t.Fatalf("exit status = %d, want 7", shell.ExitStatus())
			}
			if data, err := os.ReadFile(profilePath); err != nil || string(data) != profile {
				t.Fatalf("profile changed: %q, %v", data, err)
			}
			if files, err := os.ReadDir(runtimeDir); err != nil || len(files) != 0 {
				t.Fatalf("session files leaked: %v, %v", files, err)
			}
		})
	}
}

func TestIntegrationRejectsUnsupportedShells(t *testing.T) {
	for _, shell := range []string{"", "bash", "/bin/fish", "/bin/bash\n", "/bin/bash;touch /tmp/no"} {
		if command := integrationCommand(shell); command != "" {
			t.Errorf("unsupported shell %q enabled integration", shell)
		}
	}
}
