package sshconn

import (
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// RemoteSystem is the operating system reported by an authenticated SSH host:
// a distribution where /etc/os-release names one this client has a badge for, and
// otherwise just its family. Unknown keeps rendering and persistence honest when
// the server refuses command sessions or does not expose enough information.
type RemoteSystem uint8

const (
	SystemUnknown RemoteSystem = iota
	SystemLinux
	SystemUbuntu
	SystemWindows
	SystemDarwin
	SystemDebian
	SystemFedora
	SystemAlpine
	SystemArch
	SystemCentOS
	SystemRedHat
	SystemRocky
	SystemAlma
	SystemOpenSUSE
	SystemKali
	SystemMint
	SystemRaspberryPi
	SystemFreeBSD
	SystemNixOS
	SystemGentoo
	SystemManjaro
)

// systemNames is each system's persisted name. An /etc/os-release ID that has a
// badge is the same word, except where the ID is not what people call the system.
var systemNames = [...]string{
	SystemLinux: "linux", SystemUbuntu: "ubuntu", SystemWindows: "windows", SystemDarwin: "darwin",
	SystemDebian: "debian", SystemFedora: "fedora", SystemAlpine: "alpine", SystemArch: "arch",
	SystemCentOS: "centos", SystemRedHat: "rhel", SystemRocky: "rocky", SystemAlma: "almalinux",
	SystemOpenSUSE: "opensuse", SystemKali: "kali", SystemMint: "linuxmint", SystemRaspberryPi: "raspbian",
	SystemFreeBSD: "freebsd", SystemNixOS: "nixos", SystemGentoo: "gentoo", SystemManjaro: "manjaro",
}

func (system RemoteSystem) String() string {
	if int(system) < len(systemNames) {
		return systemNames[system]
	}
	return ""
}

// IsLinux reports whether the system is a Linux distribution or Linux itself.
func (system RemoteSystem) IsLinux() bool {
	switch system {
	case SystemUnknown, SystemWindows, SystemDarwin, SystemFreeBSD:
		return false
	}
	return int(system) < len(systemNames)
}

// ParseRemoteSystem restores a persisted system.
func ParseRemoteSystem(value string) RemoteSystem {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "macos" {
		return SystemDarwin
	}
	for system := SystemLinux; int(system) < len(systemNames); system++ {
		if systemNames[system] == value {
			return system
		}
	}
	return SystemUnknown
}

// osReleaseIDs maps an /etc/os-release ID to its system when the ID differs from
// the persisted name or has variants.
var osReleaseIDs = map[string]RemoteSystem{
	"opensuse-leap": SystemOpenSUSE, "opensuse-tumbleweed": SystemOpenSUSE, "opensuse-slowroll": SystemOpenSUSE,
	"rhel": SystemRedHat, "almalinux": SystemAlma, "rocky": SystemRocky, "raspbian": SystemRaspberryPi,
	"linuxmint": SystemMint, "arch": SystemArch, "archarm": SystemArch,
}

const remoteSystemCommand = `printf 'kernel=%s\n' "$(uname -s 2>/dev/null)"; if [ -r /etc/os-release ]; then . /etc/os-release; printf 'id=%s\n' "$ID"; fi`

// standardImplementation reports whether the server's identification string
// names an SSH implementation whose optional protocol behavior is safe to use
// beside an interactive shell. Only these receive the system and shell
// integration probes, which open a second session, and the locale environment
// request. A gateway may answer any of those by ending the whole connection,
// so an unrecognized banner only gets the pty and shell its menu needs.
// Tailscale SSH is a full server of its own, not a menu gateway: it names
// itself "Tailscale" and answers command channels like the servers above.
func standardImplementation(banner string) bool {
	banner = strings.ToLower(banner)
	return strings.Contains(banner, "openssh") ||
		strings.Contains(banner, "dropbear") ||
		strings.Contains(banner, "libssh") ||
		strings.Contains(banner, "tailscale")
}

// networkApplianceBanner reports SSH servers that are really the management CLI
// of a network device. These devices commonly allow one session at a time, and
// some answer a second session with an SSH_MSG_DISCONNECT that omits the
// mandatory language tag (which x/crypto/ssh reports as an unmarshal error).
// The name list is only a hint: shellProbeSafe is what actually guards sessions,
// because a vendor string can be missing, obfuscated or simply unknown.
func networkApplianceBanner(banner string) bool {
	banner = strings.ToLower(banner)
	for _, vendor := range []string{
		"huawei", "h3c", "cisco", "ruijie", "juniper", "mikrotik", "routeros",
		"arista", "fortinet", "paloalto", "zyxel", "tp-link", "d-link", "netgear",
		"zte", "brocade", "extreme", "big-ip",
	} {
		if strings.Contains(banner, vendor) {
			return true
		}
	}
	return false
}

// shellProbeSafe reports whether Motty may open an auxiliary session next to the
// user's shell. It is deliberately a positive allow-list: only a host that
// identifies itself as a general-purpose operating system is considered safe.
// An unknown identification string may belong to a single-session network
// appliance, which can answer a second session by tearing the whole transport
// down (the malformed disconnect and the channel-open "<nil>" seen in the
// field). Guessing from a vendor block-list is not enough, so anything not
// positively recognised is started as one plain shell with no probe at all.
// Tailscale SSH is a full server of its own even though it names neither an
// OpenSSH build nor a distribution (issue #198).
func shellProbeSafe(serverVersion string) bool {
	if strings.Contains(strings.ToLower(serverVersion), "tailscale") {
		return true
	}
	switch classifyBanner(serverVersion) {
	case SystemUbuntu, SystemDebian, SystemWindows, SystemDarwin, SystemFreeBSD:
		return true
	}
	return false
}

// SafeForAuxiliaryChannels reports whether Motty may open an optional second
// channel (an SFTP subsystem, a stats command, another shell, a probe) on an
// established connection. Only a server that positively identifies itself as a
// general-purpose operating system qualifies; anything else may be a
// single-session appliance whose transport dies when a second session appears.
// Callers keep using the shell itself regardless; this only governs extras.
func SafeForAuxiliaryChannels(serverVersion string) bool { return shellProbeSafe(serverVersion) }

// classifyBanner is what the server's identification string alone says. A
// distribution banner is only a first guess: derivatives share their parent's
// OpenSSH, so a Linux guess is refined by asking the host.
func classifyBanner(banner string) RemoteSystem {
	banner = strings.ToLower(banner)
	switch {
	case strings.Contains(banner, "win32-openssh"), strings.Contains(banner, "windows"), strings.Contains(banner, "microsoft"):
		return SystemWindows
	case strings.Contains(banner, "darwin"), strings.Contains(banner, "macos"):
		return SystemDarwin
	case strings.Contains(banner, "ubuntu"):
		return SystemUbuntu
	case strings.Contains(banner, "debian"):
		return SystemDebian
	case strings.Contains(banner, "freebsd"):
		return SystemFreeBSD
	}
	return SystemUnknown
}

// classifyProbe reads the output of remoteSystemCommand: the kernel name and,
// where the host has one, the /etc/os-release ID.
func classifyProbe(output string) RemoteSystem {
	var kernel, id string
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "kernel":
			kernel = strings.ToLower(strings.TrimSpace(value))
		case "id":
			id = strings.ToLower(strings.Trim(strings.TrimSpace(value), `"'`))
		}
	}
	switch {
	case strings.HasPrefix(kernel, "darwin"):
		return SystemDarwin
	case strings.HasPrefix(kernel, "freebsd"):
		return SystemFreeBSD
	case strings.Contains(kernel, "mingw"), strings.Contains(kernel, "cygwin"), strings.Contains(kernel, "msys"), strings.Contains(kernel, "windows"):
		return SystemWindows
	}
	if id != "" {
		if system, ok := osReleaseIDs[id]; ok {
			return system
		}
		if system := ParseRemoteSystem(id); system != SystemUnknown && system.IsLinux() {
			return system
		}
	}
	if strings.HasPrefix(kernel, "linux") {
		return SystemLinux
	}
	return SystemUnknown
}

// detectRemoteSystem asks the host what it is when the banner could not say, or
// said only a Linux distribution that a derivative may share. The answer is the
// banner's guess when the host refuses a command session. A transport-level
// failure is returned as an error so the caller can stop using the connection
// instead of swallowing the cause and opening the shell on a dead client.
func detectRemoteSystem(client *ssh.Client, banner string) (RemoteSystem, error) {
	guess := classifyBanner(banner)
	if guess == SystemWindows || guess == SystemDarwin || guess == SystemFreeBSD {
		return guess, nil
	}
	session, err := client.NewSession()
	if err != nil {
		if transportGone(err) {
			return guess, err
		}
		return guess, nil
	}
	timer := time.AfterFunc(1500*time.Millisecond, func() { _ = session.Close() })
	output, err := session.Output(remoteSystemCommand)
	if !timer.Stop() || err != nil {
		if transportGone(err) {
			return guess, err
		}
		return guess, nil
	}
	system := classifyProbe(string(output))
	if system == SystemUnknown || system == SystemLinux && guess.IsLinux() {
		// A derivative with no badge of its own (Pop!_OS, Zorin) keeps the family
		// its banner named rather than falling back to plain Linux.
		return guess, nil
	}
	return system, nil
}
