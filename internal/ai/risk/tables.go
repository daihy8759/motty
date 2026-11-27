package risk

import "strings"

// flagRule raises the level when a flag is present.
type flagRule struct {
	short string
	long  []string
	level Level
	why   string
}

// rule describes how one command name is classified. The base level applies
// when no subcommand matches; subs maps the subcommand (the subIdx-th
// positional argument) to a level; flags raise it; check can add findings that
// need real inspection of the arguments. Rules can only raise a level, so
// commands that are read-only by default but dangerous with some arguments use
// base Low and a check.
type rule struct {
	level  Level
	subs   map[string]Level
	subIdx int
	def    Level // level of an unlisted subcommand when hasDef
	hasDef bool
	optArg map[string]bool // options that consume a separate value
	nested map[string]*rule
	flags  []flagRule
	check  func(c *call, a *acc)
	safer  string
}

type subSet struct {
	l     Level
	names string
}

func subs(sets ...subSet) map[string]Level {
	m := map[string]Level{}
	for _, s := range sets {
		for _, n := range strings.Fields(s.names) {
			m[n] = s.l
		}
	}
	return m
}

func S(l Level, names string) subSet { return subSet{l, names} }

var (
	rules    = map[string]*rule{}
	wrappers = map[string]*wrapSpec{}
)

func reg(names string, r *rule) {
	for _, n := range strings.Fields(names) {
		rules[n] = r
	}
}

func low(names string) { reg(names, &rule{level: Low}) }

func lookupRule(name string) *rule {
	if r := rules[name]; r != nil {
		return r
	}
	for _, pre := range []string{"mkfs", "fsck", "mkswap"} {
		if strings.HasPrefix(name, pre) {
			return rules[pre]
		}
	}
	return nil
}

func wrap(names string, w *wrapSpec) {
	for _, n := range strings.Fields(names) {
		wrappers[n] = w
	}
}

const (
	saferRm     = "List what matches first (ls), delete a named path rather than a wildcard, or move it to a trash directory"
	saferNoSudo = "Run it without elevated privileges if possible"
)

func init() {
	wrap("sudo", &wrapSpec{level: High, why: "runs a command as another user (usually root)", env: true, safer: saferNoSudo,
		optArg: set("-u -g -h -p -C -T -r -t -U -D -R")})
	wrap("doas", &wrapSpec{level: High, why: "runs a command as another user (usually root)", optArg: set("-u -C"), safer: saferNoSudo})
	wrap("pkexec", &wrapSpec{level: High, why: "runs a command as another user (usually root)", optArg: set("--user")})
	wrap("runuser", &wrapSpec{level: High, why: "runs a command as another user", optArg: set("-u -g -G -s -l")})
	wrap("chroot", &wrapSpec{level: High, why: "runs a command in another root directory", pos: 1})
	wrap("env", &wrapSpec{level: Low, why: "runs a command with a changed environment", env: true, optArg: set("-u -C -S")})
	wrap("nohup setsid fakeroot unbuffer chronic busybox builtin exec time", &wrapSpec{level: Low, why: "runs another command", optArg: set("-a -f -o")})
	wrap("command", &wrapSpec{level: Low, why: "runs another command"})
	wrap("nice", &wrapSpec{level: Low, why: "runs another command", optArg: set("-n")})
	wrap("ionice", &wrapSpec{level: Low, why: "runs another command", optArg: set("-c -n -p -P -u")})
	wrap("stdbuf", &wrapSpec{level: Low, why: "runs another command", optArg: set("-i -o -e")})
	wrap("timeout", &wrapSpec{level: Low, why: "runs another command", pos: 1, optArg: set("-s -k")})
	wrap("flock", &wrapSpec{level: Low, why: "runs another command", pos: 1, optArg: set("-w -E")})
	wrap("taskset", &wrapSpec{level: Low, why: "runs another command", pos: 1, optArg: set("-c")})
	wrap("xargs", &wrapSpec{level: Low, why: "runs a command once per input item", optArg: set("-n -I -L -P -d -E -s -a -J -R -S")})
	wrap("watch", &wrapSpec{level: Low, why: "repeatedly runs a command line", optArg: set("-n -w"), script: true})
	wrap("parallel", &wrapSpec{level: High, why: "runs generated command lines that cannot be reviewed", optArg: set("-j -S -a")})

	// Read-only inspection.
	low(`ls ll la dir vdir cat tac bat nl head tail less more most grep egrep fgrep zgrep rg ag ack ps pgrep pidof top htop btop atop iotop
		df du free uptime uname whoami id groups pwd echo printf date stat wc sort uniq cut tr paste column fold fmt expand unexpand comm diff cmp
		md5sum sha1sum sha224sum sha256sum sha384sum sha512sum b2sum cksum sum shasum md5 file which type whereis whence hash
		basename dirname realpath readlink pathchk lsblk lsof lscpu lsmod lspci lsusb lsipc lsns lslogins lsattr lsscsi lshw dmidecode inxi
		getfacl getfattr findmnt blkid mountpoint w who users last lastb lastlog finger vmstat iostat mpstat sar nproc getconf locale arch
		nslookup dig host whois ping ping6 traceroute traceroute6 tracepath mtr ss netstat ifstat nstat arp printenv tree jq xxd hexdump od
		strings seq sleep true false : test [ yes tty clear tput history man help info apropos whatis tldr cal ncal bc dc expr factor numfmt
		getent logname readelf objdump nm ldd size sensors smartctl systemd-analyze apt-cache apt-file dpkg-query modinfo tput rev shuf
		base64 base32 zcat zless bzcat xzcat lz4cat zipinfo cd pushd popd dirs export unset set shift read local declare typeset readonly let
		return exit break continue wait jobs fg bg umask ulimit shopt unalias disown mapfile readarray getopts printenv sha3sum pr tsort
		ntpq chronyc lvs vgs pvs lvdisplay vgdisplay pvdisplay lvscan vgscan pvscan lvmdiskscan showmount zdump iwconfig iwlist`)

	// Writers and deleters.
	reg("rm", &rule{level: High, check: rmCheck, safer: saferRm})
	reg("rmdir unlink", &rule{level: High, check: rmCheck, safer: saferRm})
	reg("shred", &rule{level: High, check: shredCheck, safer: saferRm})
	reg("mv", &rule{level: Medium, check: mvCheck})
	reg("cp", &rule{level: Medium, check: mvCheck})
	reg("rsync", &rule{level: Medium, check: rsyncCheck})
	reg("tee", &rule{level: Low, check: writerCheck})
	reg("touch mkdir truncate install ln mktemp mkfifo patch split csplit rename", &rule{level: Medium, check: writerCheck})
	reg("mknod", &rule{level: High, check: writerCheck})
	reg("dd", &rule{level: Low, check: ddCheck, safer: "Double check of= with lsblk; write to a file first"})
	reg("ddrescue", &rule{level: High, check: writerCheck})
	reg("chmod chown chgrp", &rule{level: High, check: chmodCheck})
	reg("chattr setfacl setcap chcon semanage setenforce", &rule{level: High})
	reg("restorecon", &rule{level: Medium})
	reg("find", &rule{level: Low, check: findCheck})
	reg("tar bsdtar", &rule{level: Low, check: tarCheck})
	reg("sed", &rule{level: Low, check: sedCheck})
	reg("awk gawk mawk nawk", &rule{level: Low, check: awkCheck})
	reg("yq", &rule{level: Low, flags: []flagRule{{short: "i", long: []string{"--inplace"}, level: Medium, why: "edits files in place"}}})
	reg("sort", &rule{level: Low, flags: []flagRule{{short: "o", long: []string{"--output"}, level: Medium, why: "writes to a file"}}})
	reg("uniq", &rule{level: Low, check: func(c *call, a *acc) {
		if len(positional(c.args, set("-f -s -w"))) >= 2 {
			a.add(Medium, "uniq writes to an output file", "")
		}
	}})
	reg("gzip gunzip bzip2 bunzip2 xz unxz zstd lz4", &rule{level: Low, check: compressCheck})
	reg("unzip", &rule{level: Low, check: func(c *call, a *acc) {
		if !hasFlag(c.args, "ltpZ") {
			a.add(Medium, "unzip extracts files", "List the archive first with unzip -l")
		}
	}})
	reg("zip 7z 7za 7zr cpio ar", &rule{level: Medium})
	reg("curl", &rule{level: Low, check: curlCheck})
	reg("wget wget2", &rule{level: Low, check: wgetCheck})
	reg("dmesg", &rule{level: Low, flags: []flagRule{{short: "cC", long: []string{"--clear", "--read-clear"}, level: Medium, why: "clears the kernel log"}}})
	reg("fuser", &rule{level: Low, flags: []flagRule{{short: "k", long: []string{"--kill"}, level: High, why: "kills processes"}}})
	reg("make gmake ninja just", &rule{level: Low, check: func(c *call, a *acc) {
		if !hasFlag(c.args, "npq", "--dry-run", "--just-print", "--recon", "--print-data-base", "--question") {
			a.add(High, c.name+" runs build recipes that cannot be reviewed", "Run make -n to preview the commands")
		}
	}})
	reg("hostname", &rule{level: Low, check: func(c *call, a *acc) {
		if len(positional(c.args, nil)) > 0 || hasFlag(c.args, "Fb", "--file") {
			a.add(High, "hostname: changes the host name", "")
		}
	}})
	reg("date", &rule{level: Low, check: func(c *call, a *acc) {
		for _, w := range positional(c.args, set("-d -r -f --date --reference --file")) {
			if !strings.HasPrefix(w.text, "+") {
				a.add(High, "date: sets the system clock", "")
			}
		}
		if hasFlag(c.args, "s", "--set") {
			a.add(High, "date: sets the system clock", "")
		}
	}})
	reg("sysctl", &rule{level: Low, check: func(c *call, a *acc) {
		for _, w := range positional(c.args, nil) {
			if strings.Contains(w.text, "=") {
				a.add(High, "sysctl: changes a kernel parameter", "")
			}
		}
		if hasFlag(c.args, "wp", "--write", "--load", "--system") {
			a.add(High, "sysctl: changes kernel parameters", "")
		}
	}})
	reg("mount", &rule{level: Low, check: func(c *call, a *acc) {
		if len(positional(c.args, set("-t -o -L -U"))) > 0 {
			a.add(High, "mount: changes mounted filesystems", "")
		}
	}})
	reg("umount swapoff", &rule{level: High})
	reg("swapon", &rule{level: Low, check: func(c *call, a *acc) {
		if len(positional(c.args, nil)) > 0 || hasFlag(c.args, "aeL") {
			a.add(High, "swapon: changes swap configuration", "")
		}
	}})
	reg("modprobe insmod rmmod depmod kexec-tools", &rule{level: High})
	reg("journalctl", &rule{level: Low, check: func(c *call, a *acc) {
		for _, w := range c.args {
			switch {
			case strings.HasPrefix(w.text, "--vacuum"):
				a.add(High, "journalctl: deletes archived logs", "")
			case w.text == "--rotate" || w.text == "--flush" || w.text == "--sync" || w.text == "--relinquish-var":
				a.add(Medium, "journalctl: changes journal files", "")
			}
		}
	}})
	reg("logrotate", &rule{level: High, flags: nil})

	// Privileges and accounts.
	reg("su", &rule{level: High, check: suCheck, safer: saferNoSudo})
	reg("useradd userdel usermod adduser deluser groupadd groupdel groupmod addgroup delgroup passwd chpasswd newusers gpasswd chage chsh chfn visudo vipw vigr",
		&rule{level: High})
	reg("eval", &rule{level: High, check: evalCheck, safer: "Run the command directly instead of building it as text"})
	reg("source .", &rule{level: High, check: func(c *call, a *acc) {
		a.recordApproval(c.name + " runs shell code from a file that cannot be reviewed")
	}, safer: "Read the file first, then run its commands"})
	reg("trap", &rule{level: Low, check: func(c *call, a *acc) {
		pos := positional(c.args, set("-p"))
		if len(pos) >= 2 && !hasFlag(c.args, "lp") {
			if pos[0].dyn() {
				a.add(High, "trap: handler is built from variables", "")
			} else {
				a.merge(c.s.analyze(pos[0].text, c.depth+1))
			}
		}
	}})
	reg("alias", &rule{level: Medium})
	reg("kill", &rule{level: High, check: killCheck, safer: "Find the process first with ps/pgrep, and try SIGTERM before SIGKILL"})
	reg("killall pkill skill", &rule{level: High, check: pkillCheck, safer: "List matches first with pgrep -a"})
	reg("killall5", &rule{level: Critical})
	reg("renice", &rule{level: Medium})
	reg("at batch atrm systemd-run", &rule{level: High})
	reg("atq", &rule{level: Low})
	reg("crontab", &rule{level: Low, check: func(c *call, a *acc) {
		if hasFlag(c.args, "eri") || len(positional(c.args, set("-u"))) > 0 {
			a.add(High, "crontab: edits scheduled jobs", "")
		}
	}})
	reg("shutdown", &rule{level: Low, check: func(c *call, a *acc) {
		if hasFlag(c.args, "c", "--cancel") {
			a.add(Medium, "shutdown: cancels a pending shutdown", "")
		} else {
			a.add(Critical, "shutdown: powers off or halts the machine", "")
		}
	}})
	reg("reboot halt poweroff kexec", &rule{level: Critical})
	reg("init telinit", &rule{level: High, check: func(c *call, a *acc) {
		for _, w := range positional(c.args, nil) {
			if w.text == "0" || w.text == "6" {
				a.add(Critical, c.name+": halts or reboots the machine", "")
			}
		}
	}})
	reg("tmux", &rule{level: High, subs: subs(S(Low, "ls list-sessions list-windows list-panes list-clients list-commands show-options show-environment display-message capture-pane has-session info show-messages list-buffers show-buffer")),
		optArg: set("-L -S -f -c -T")})
	reg("screen", &rule{level: Low, check: func(c *call, a *acc) {
		for _, w := range c.args {
			switch w.text {
			case "-ls", "-list", "-v", "--version", "-wipe":
				return
			}
		}
		a.add(High, "screen: starts or controls terminal sessions that run commands", "")
	}})
	reg("vi vim nvim nano emacs ed ex pico micro", &rule{level: Medium})
	reg("strace ltrace tcpdump nmap ftp lftp sftp scp ssh-agent aria2c", &rule{level: Medium})
	reg("gdb lldb perf", &rule{level: High})
	reg("nc ncat netcat telnet socat", &rule{level: Medium, check: ncCheck})
	reg("unshare nsenter", &rule{level: High})

	// Remote.
	reg("ssh", &rule{level: Medium, check: sshCheck})
	reg("ssh-copy-id sshfs mosh rsh", &rule{level: Medium})
	reg("ssh-keygen", &rule{level: Low, check: func(c *call, a *acc) {
		if !hasFlag(c.args, "lFyBQ") {
			a.add(Medium, "ssh-keygen: creates or modifies key files", "")
		}
	}})
	reg("ssh-add", &rule{level: Low, check: func(c *call, a *acc) {
		if !hasFlag(c.args, "lL") {
			a.add(Medium, "ssh-add: changes the agent's keys", "")
		}
	}})
	reg("ssh-keyscan", &rule{level: Low})
	reg("openssl", &rule{level: Low, check: func(c *call, a *acc) {
		pos := positional(c.args, nil)
		if len(pos) == 0 {
			return
		}
		switch pos[0].text {
		case "version", "x509", "s_client", "verify", "list", "ciphers", "dgst", "help", "crl", "asn1parse", "rand":
			if hasFlag(c.args, "", "-out", "-in-place") || (pos[0].text == "rand" && hasFlag(c.args, "", "-out")) {
				a.add(Medium, "openssl: writes a file", "")
			}
		default:
			a.add(Medium, "openssl: generates or converts key material", "")
		}
	}})
	reg("gpg gpg2", &rule{level: Low, check: func(c *call, a *acc) {
		for _, w := range c.args {
			if strings.HasPrefix(w.text, "--delete") {
				a.add(High, "gpg: deletes keys", "")
			}
		}
		if !hasFlag(c.args, "kK", "--list-keys", "--list-secret-keys", "--list-sigs", "--fingerprint", "--verify", "--version", "--list-public-keys") {
			a.add(Medium, "gpg: changes the keyring or writes files", "")
		}
	}})

	// Version control.
	reg("git", gitRule())

	// Containers and clusters.
	d := dockerRule()
	reg("docker podman nerdctl", d)
	reg("kubectl oc", kubectlRule())
	reg("helm", &rule{level: Low, subs: subs(
		S(Low, "list ls status get show search template lint version env history verify"),
		S(Medium, "repo pull fetch package plugin create dependency dep"),
		S(High, "install upgrade uninstall delete rollback test")), hasDef: true, def: High,
		optArg: set("-n --namespace --kube-context --kubeconfig")})
	reg("terraform tofu", &rule{level: High, subs: subs(
		S(Low, "plan show output validate version providers graph"), S(Medium, "init fmt refresh get")), hasDef: true, def: High,
		optArg: set("-chdir")})
	reg("aws", &rule{level: Low, check: awsCheck})

	// Service managers.
	reg("systemctl", &rule{level: Low, check: systemctlCheck, hasDef: true, def: High, optArg: set("-H -M -p -t -s -n -o --host --machine --property --type --signal --lines --output"),
		subs: subs(
			S(Low, "status show list-units list-unit-files list-timers list-sockets list-dependencies list-jobs list-machines is-active is-enabled is-failed is-system-running cat get-default show-environment help"),
			S(Medium, "start restart reload try-restart reload-or-restart try-reload-or-restart condrestart daemon-reload daemon-reexec enable reenable preset set-environment unset-environment reset-failed link import-environment"),
			S(High, "stop disable mask unmask kill isolate edit revert set-default rescue emergency default set-property switch-root suspend hibernate hybrid-sleep"),
			S(Critical, "poweroff reboot halt kexec"))})
	reg("service", &rule{level: Low, subIdx: 1, check: serviceCheck, hasDef: true, def: High,
		subs: subs(S(Low, "status"), S(Medium, "start restart reload force-reload condrestart try-restart"), S(High, "stop"))})
	for _, n := range []string{"loginctl", "hostnamectl", "timedatectl", "localectl", "busctl", "machinectl", "coredumpctl", "networkctl", "resolvectl", "systemd-resolve"} {
		reg(n, &rule{level: Low, check: ctlCheck})
	}

	// Packages.
	reg("apt apt-get aptitude nala", &rule{level: Medium, hasDef: true, def: Medium, optArg: set("-o -c -t -a --target-release"),
		subs: subs(S(Low, "list show search policy depends rdepends showpkg madison changelog moo"),
			S(Medium, "install update upgrade full-upgrade dist-upgrade source download build-dep reinstall clean autoclean satisfy edit-sources"),
			S(High, "remove purge autoremove autopurge"))})
	reg("yum dnf microdnf zypper", &rule{level: Medium, hasDef: true, def: Medium, optArg: set("-c -y --enablerepo --disablerepo"),
		subs: subs(S(Low, "list info search provides repolist history check-update deplist repoquery whatprovides"),
			S(Medium, "install update upgrade reinstall downgrade makecache clean"),
			S(High, "remove erase autoremove swap distro-sync"))})
	reg("apk", &rule{level: Medium, hasDef: true, def: Medium,
		subs: subs(S(Low, "info list search stats version dot policy"), S(Medium, "add update upgrade fix cache"), S(High, "del"))})
	reg("pacman", &rule{level: Low, check: pacmanCheck})
	reg("dpkg", &rule{level: Low, check: dpkgCheck})
	reg("rpm", &rule{level: Low, check: rpmCheck})
	reg("brew", &rule{level: Medium, hasDef: true, def: Medium,
		subs: subs(S(Low, "list ls info search outdated deps uses leaves config doctor desc home log options --version -v"),
			S(Medium, "install update upgrade reinstall tap link unlink pin unpin cleanup services"),
			S(High, "uninstall remove rm untap autoremove"))})
	reg("npm pnpm yarn bun", &rule{level: Medium, hasDef: true, def: Medium,
		subs: subs(S(Low, "ls list ll la view info show search outdated audit why explain ping whoami prefix root bin help version v doctor fund"),
			S(Medium, "install i add ci update up upgrade rebuild dedupe link pack init create cache config"),
			S(High, "uninstall remove rm un unlink publish unpublish deprecate login logout adduser token owner access dist-tag run run-script start test t exec x dlx"))})
	reg("npx bunx", &rule{level: High, safer: "Install and review the package first"})
	reg("pip pip3", &rule{level: Medium, hasDef: true, def: Medium,
		subs: subs(S(Low, "list show freeze check search config debug help inspect hash"), S(Medium, "install download wheel cache"), S(High, "uninstall"))})
	reg("gem", &rule{level: Medium, hasDef: true, def: Medium,
		subs: subs(S(Low, "list info search query environment help which contents dependency outdated"), S(Medium, "install update cleanup"), S(High, "uninstall"))})
	reg("cargo", &rule{level: Medium, hasDef: true, def: Medium,
		subs: subs(S(Low, "tree metadata version search locate-project pkgid verify-project help"),
			S(Medium, "build check test doc fetch update add fmt clippy bench install clean"),
			S(High, "uninstall remove publish yank login run"))})
	reg("go", &rule{level: Medium, hasDef: true, def: Medium,
		subs: subs(S(Low, "version env list doc help"), S(Medium, "build get install mod fmt clean tool vet test"), S(High, "run generate"))})
	reg("snap flatpak", &rule{level: Medium, hasDef: true, def: Medium,
		subs: subs(S(Low, "list info find search"), S(Medium, "install refresh update"), S(High, "remove uninstall"))})

	// Networking and firewall.
	reg("iptables ip6tables iptables-legacy ip6tables-legacy", &rule{level: Low, check: iptablesCheck})
	reg("iptables-restore ip6tables-restore ebtables arptables ipset", &rule{level: High})
	reg("iptables-save ip6tables-save", &rule{level: Low})
	reg("nft", &rule{level: Low, check: nftCheck})
	reg("ufw", &rule{level: High, hasDef: true, def: High,
		subs: subs(S(Low, "status show version"), S(Critical, "reset disable"))})
	reg("firewall-cmd", &rule{level: Low, check: func(c *call, a *acc) {
		for _, w := range c.args {
			if strings.HasPrefix(w.text, "--") {
				ok := false
				for _, pre := range []string{"--list", "--get", "--state", "--query", "--info", "--version", "--help", "--permanent", "--zone", "--quiet"} {
					if strings.HasPrefix(w.text, pre) {
						ok = true
					}
				}
				if !ok {
					a.add(High, "firewall-cmd: changes firewall rules", "")
				}
			}
		}
	}})
	reg("ip", &rule{level: Low, check: ipCheck})
	reg("ifconfig", &rule{level: Low, check: func(c *call, a *acc) {
		if len(positional(c.args, nil)) >= 2 {
			a.add(High, "ifconfig: changes an interface", "")
		}
	}})
	reg("route", &rule{level: Low, check: func(c *call, a *acc) {
		for _, w := range positional(c.args, nil) {
			switch w.text {
			case "add", "del", "delete", "flush", "change":
				a.add(High, "route: changes the routing table", "")
			}
		}
	}})
	reg("ifup ifdown dhclient dhcpcd netplan wg-quick", &rule{level: High})
	reg("nmcli", &rule{level: Low, check: nmcliCheck})
	reg("ethtool", &rule{level: Low, check: func(c *call, a *acc) {
		if hasFlag(c.args, "sKAGCEfrtLNnW") {
			a.add(High, "ethtool: changes interface settings", "")
		}
	}})

	// Disks.
	reg("mkfs mkswap mke2fs mkdosfs mkntfs blkdiscard grub-install", &rule{level: Critical})
	reg("fsck tune2fs resize2fs e2fsck xfs_repair xfs_growfs badblocks losetup-set", &rule{level: High})
	reg("fdisk", &rule{level: Low, check: func(c *call, a *acc) {
		if !hasFlag(c.args, "ls", "--list", "--show-size") {
			a.add(Critical, "fdisk: edits a partition table", "Use fdisk -l to list partitions")
		}
	}})
	reg("sfdisk", &rule{level: Low, check: func(c *call, a *acc) {
		if !hasFlag(c.args, "lsdJF", "--list", "--show-size", "--dump", "--json", "--list-free") {
			a.add(Critical, "sfdisk: edits a partition table", "")
		}
	}})
	reg("gdisk sgdisk", &rule{level: Low, check: func(c *call, a *acc) {
		if !hasFlag(c.args, "lp", "--print", "--list") {
			a.add(Critical, c.name+": edits a partition table", "")
		}
	}})
	reg("cfdisk", &rule{level: Critical})
	reg("parted", &rule{level: Low, check: partedCheck})
	reg("wipefs", &rule{level: Low, check: func(c *call, a *acc) {
		if hasFlag(c.args, "aofb", "--all", "--offset", "--force", "--backup") {
			a.add(Critical, "wipefs: erases filesystem signatures", "")
		}
	}})
	reg("hdparm", &rule{level: Medium, check: func(c *call, a *acc) {
		for _, w := range c.args {
			if strings.HasPrefix(w.text, "--security") || strings.HasPrefix(w.text, "--dco") || w.text == "--yes-i-know-what-i-am-doing" || strings.HasPrefix(w.text, "--trim") {
				a.add(Critical, "hdparm: can erase or brick a disk", "")
			}
		}
	}})
	reg("cryptsetup", &rule{level: High, hasDef: true, def: High, subs: subs(
		S(Low, "status luksDump isLuks benchmark --version"), S(Medium, "open luksOpen close luksClose"),
		S(Critical, "luksFormat erase luksErase luksKillSlot luksRemoveKey reencrypt luksAddKey luksChangeKey"))})
	reg("lvremove vgremove pvremove lvreduce vgreduce lvresize vgcfgrestore lvconvert", &rule{level: Critical})
	reg("lvcreate vgcreate pvcreate lvextend vgextend lvrename vgrename pvmove", &rule{level: High})
	reg("mdadm", &rule{level: Low, check: func(c *call, a *acc) {
		if hasFlag(c.args, "", "--zero-superblock", "--create", "--remove", "--fail") || hasFlag(c.args, "C") {
			a.add(Critical, "mdadm: destroys or rebuilds an array", "")
		} else if !hasFlag(c.args, "DEQsV", "--detail", "--examine", "--query", "--scan", "--version") {
			a.add(High, "mdadm: changes an array", "")
		}
	}})
	reg("losetup", &rule{level: Low, check: func(c *call, a *acc) {
		if !hasFlag(c.args, "alljO", "--list", "--all", "--output") {
			a.add(High, "losetup: changes loop devices", "")
		}
	}})
	reg("efibootmgr", &rule{level: Low, check: func(c *call, a *acc) {
		if hasFlag(c.args, "BcNoaAnTt", "--delete-bootnum", "--create", "--bootorder") {
			a.add(Critical, "efibootmgr: changes firmware boot entries", "")
		}
	}})
	reg("update-grub grub-mkconfig update-initramfs mkinitcpio dracut update-alternatives ldconfig", &rule{level: High})
	reg("btrfs", &rule{level: High, hasDef: true, def: High, subs: subs(S(Low, "filesystem subvolume device"))})
	reg("zfs zpool", &rule{level: High, hasDef: true, def: High, subs: subs(
		S(Low, "list get status iostat history version events"), S(Critical, "destroy labelclear"))})
}

func suCheck(c *call, a *acc) {
	args := c.args
	for i, w := range args {
		t := w.text
		if (t == "-c" || t == "--command" || (len(t) > 1 && t[0] == '-' && t[1] != '-' && strings.IndexByte(t, 'c') >= 0)) && i+1 < len(args) {
			if args[i+1].dyn() {
				a.add(High, "su -c runs a command built from variables", "")
				return
			}
			a.merge(c.s.analyze(args[i+1].text, c.depth+1))
			return
		}
		if strings.HasPrefix(t, "--command=") {
			a.merge(c.s.analyze(strings.TrimPrefix(t, "--command="), c.depth+1))
			return
		}
	}
}

func evalCheck(c *call, a *acc) {
	if len(c.args) == 0 {
		return
	}
	if anyDyn(c.args) {
		a.requireApproval(High, "eval runs text built from variables or substitutions", "")
	}
	a.merge(c.s.analyze(joinText(c.args), c.depth+1))
}

func rmCheck(c *call, a *acc) {
	recursive := hasFlag(c.args, "rR", "--recursive")
	if hasFlag(c.args, "", "--no-preserve-root") {
		a.add(Critical, c.name+": disables the protection of the filesystem root", "")
	}
	if recursive {
		a.add(High, c.name+": recursive delete", saferRm)
	}
	for _, w := range positional(c.args, nil) {
		if r := delDanger(w, recursive, true); r != "" {
			a.add(Critical, c.name+": "+r, saferRm)
		}
		p, _ := normPath(w.text)
		if sensitive(p) {
			a.add(Critical, c.name+": removes SSH keys, SSH or account configuration, or boot configuration", "Move the file aside instead and keep a second session open")
		}
	}
}

func shredCheck(c *call, a *acc) {
	for _, w := range positional(c.args, set("-n -s --iterations --size")) {
		p, _ := normPath(w.text)
		if isBlockDev(p) || sensitive(p) {
			a.add(Critical, "shred: irrecoverably overwrites a device or security-sensitive file", "")
		}
	}
}

func mvCheck(c *call, a *acc) {
	pos := positional(c.args, set("-t -S --target-directory --suffix"))
	for i, w := range pos {
		last := i == len(pos)-1
		p, glob := normPath(w.text)
		if c.name == "mv" && !last {
			if r := pathDanger(p, glob, true, false); r != "" {
				a.add(Critical, "mv: moves away "+strings.TrimPrefix(r, "targets "), "")
			}
			if sensitive(p) {
				a.add(Critical, "mv: moves away SSH keys, account or boot configuration", "")
			}
			if inSystemTree(p) {
				a.add(High, "mv: moves files out of a system directory", "")
			}
		}
		if last && len(pos) >= 2 {
			if c.name == "mv" && p == "/dev/null" {
				a.add(High, "mv: discards the file by moving it to /dev/null", "")
				continue
			}
			c.s.writeTarget(w, c.name, a)
		}
	}
}

func writerCheck(c *call, a *acc) {
	args := c.args
	files := positional(args, set("-m -o -g -t -S -s -r -d -c -n --mode --owner --group --size --reference"))
	if c.name == "tee" && len(files) == 0 {
		return
	}
	if c.name == "tee" {
		a.add(Medium, "tee writes to files", "")
	}
	for _, w := range files {
		if c.name == "ddrescue" || c.name == "ln" {
			p, _ := normPath(w.text)
			if isBlockDev(p) {
				a.add(Critical, c.name+": targets a raw device", "")
			}
			continue
		}
		c.s.writeTarget(w, c.name, a)
	}
}

func ddCheck(c *call, a *acc) {
	for _, w := range c.args {
		if !strings.HasPrefix(w.text, "of=") {
			continue
		}
		v := w.text[3:]
		if w.dyn() {
			a.add(Critical, "dd: output target is computed at run time and may be a device", "")
			continue
		}
		p, _ := normPath(v)
		switch {
		case benignDev(p):
		case strings.HasPrefix(p, "/dev/"):
			a.add(Critical, "dd: writes directly to a device", "Write to a file first; check the target with lsblk")
		default:
			c.s.writeTarget(word{text: v, quoteAt: -1}, "dd", a)
		}
	}
}

func chmodCheck(c *call, a *acc) {
	recursive := hasFlag(c.args, "R", "--recursive")
	for _, w := range positional(c.args, nil) {
		if r := delDanger(w, recursive, false); r != "" {
			a.add(Critical, c.name+": "+r, "Limit the change to the specific directory that needs it")
		}
	}
}

func findCheck(c *call, a *acc) {
	args := c.args
	danger := false
	for _, w := range args {
		if strings.HasPrefix(w.text, "-") || w.text == "(" || w.text == "!" || w.text == "\\(" {
			break
		}
		p, glob := normPath(w.text)
		if pathDanger(p, glob, true, false) != "" {
			danger = true
		}
	}
	for i := 0; i < len(args); i++ {
		switch args[i].text {
		case "-delete":
			a.add(High, "find -delete removes every match", "Run the find without -delete first")
			if danger {
				a.add(Critical, "find -delete starting at the filesystem root or a system directory", "")
			}
		case "-exec", "-execdir", "-ok", "-okdir":
			j := i + 1
			for j < len(args) && args[j].text != ";" && args[j].text != "+" {
				j++
			}
			var sub acc
			c.s.words(args[i+1:j], stdin{}, c.depth+1, &sub)
			a.merge(sub)
			if danger && sub.level >= High {
				a.add(Critical, "find -exec runs a risky command from the filesystem root or a system directory", "")
			}
			i = j
		case "-fprint", "-fprint0", "-fprintf", "-fls":
			a.add(Medium, "find writes its output to a file", "")
		}
	}
}

func tarCheck(c *call, a *acc) {
	mode := byte(0)
	set1 := func(m byte) {
		if mode == 0 {
			mode = m
		}
	}
	args := c.args
	for i, w := range args {
		t := w.text
		if t == "--" {
			break
		}
		if strings.HasPrefix(t, "--") {
			name := t
			if k := strings.IndexByte(t, '='); k > 0 {
				name = t[:k]
			}
			switch name {
			case "--extract", "--get":
				set1('x')
			case "--create", "--list", "--diff", "--compare":
				set1('c')
			case "--append", "--update":
				set1('r')
			case "--delete", "--remove-files":
				a.add(High, "tar "+name+" removes data", "")
			case "--to-command", "--use-compress-program", "--checkpoint-action", "--info-script", "--new-volume-script", "--rsh-command":
				a.add(High, "tar "+name+" runs another program", "")
			case "--directory":
				v := ""
				if k := strings.IndexByte(t, '='); k > 0 {
					v = t[k+1:]
				} else if i+1 < len(args) {
					v = args[i+1].text
				}
				tarDir(v, a)
			}
			continue
		}
		cluster := ""
		switch {
		case len(t) > 1 && t[0] == '-':
			cluster = t[1:]
		case i == 0 && t != "" && t[0] != '/' && t[0] != '.':
			cluster = t
		}
		for j := 0; j < len(cluster); j++ {
			switch cluster[j] {
			case 'x':
				set1('x')
			case 'c', 't', 'd':
				set1('c')
			case 'r', 'u':
				set1('r')
			case 'C':
				if t[0] == '-' && j == len(cluster)-1 && i+1 < len(args) {
					tarDir(args[i+1].text, a)
				}
			}
		}
	}
	switch mode {
	case 'c':
	case 'x':
		a.add(Medium, "tar extracts files, possibly overwriting existing ones", "List the archive first with tar -t")
	default:
		a.add(Medium, "tar modifies an archive or its mode is unclear", "")
	}
}

func tarDir(v string, a *acc) {
	p, _ := normPath(v)
	if p == "/" || inSystemTree(p) {
		a.add(High, "tar extracts into a system directory", "Extract to a scratch directory first")
	}
}

func sedCheck(c *call, a *acc) {
	inplace := hasFlag(c.args, "i", "--in-place")
	if inplace {
		a.add(Medium, "sed -i edits files in place", "Run without -i first to preview the result")
	}
	for _, w := range c.args {
		t := w.text
		if strings.HasPrefix(t, "-") {
			continue
		}
		if t == "e" || strings.HasPrefix(t, "e ") || (strings.Count(t, "/") >= 3 && strings.HasSuffix(t, "/e")) {
			a.add(High, "sed 'e' executes commands", "")
		}
		if strings.HasPrefix(t, "w ") || strings.Contains(t, "/w ") {
			a.add(Medium, "sed writes to a file", "")
		}
		if inplace {
			p, _ := normPath(t)
			if sensitive(p) || inSystemTree(p) {
				a.add(High, "sed -i edits a system or security-sensitive file", "")
			}
		}
	}
}

func awkCheck(c *call, a *acc) {
	for i, w := range c.args {
		t := w.text
		if (t == "-i" && i+1 < len(c.args) && c.args[i+1].text == "inplace") || t == "-iinplace" {
			a.add(Medium, "awk edits files in place", "")
		}
		switch {
		case strings.Contains(t, "system(") || strings.Contains(t, "| getline") || strings.Contains(t, "|getline") ||
			strings.Contains(t, "|\"") || strings.Contains(t, "| \"") || strings.Contains(t, "|&"):
			a.add(High, "awk program can run commands", "")
		case strings.Contains(t, ">\"") || strings.Contains(t, "> \"") || strings.Contains(t, ">>") || strings.Contains(t, "> $"):
			a.add(Medium, "awk program may write files", "")
		}
	}
}

func compressCheck(c *call, a *acc) {
	if len(positional(c.args, set("-S -S"))) == 0 {
		return
	}
	if !hasFlag(c.args, "ctl", "--stdout", "--to-stdout", "--test", "--list") {
		a.add(Medium, c.name+": replaces files in place", "Use -c to write to stdout")
	}
}

func fileFlag(a *acc, v string, why string) {
	if v == "" || v == "-" || v == "/dev/null" {
		return
	}
	p, _ := normPath(v)
	switch {
	case isBlockDev(p):
		a.add(Critical, why+" to a raw device", "")
	case sensitive(p):
		a.add(High, why+" over a security-sensitive file", "")
	case inSystemTree(p):
		a.add(High, why+" under a system directory", "")
	default:
		a.add(Medium, why+" to a file", "")
	}
}

func curlCheck(c *call, a *acc) {
	args := c.args
	val := func(i *int, inline string, has bool) string {
		if has {
			return inline
		}
		if *i+1 < len(args) {
			*i++
			return args[*i].text
		}
		return ""
	}
	for i := 0; i < len(args); i++ {
		t := args[i].text
		if t == "--" {
			break
		}
		if len(t) < 2 || t[0] != '-' {
			continue
		}
		if t[1] == '-' {
			name, v, has := strings.Cut(t, "=")
			switch name {
			case "--output", "--dump-header", "--cookie-jar", "--trace", "--trace-ascii", "--stderr":
				fileFlag(a, val(&i, v, has), "curl saves output")
			case "--remote-name", "--remote-name-all", "--remote-header-name":
				a.add(Medium, "curl saves a download to a file", "Omit -O to print to the terminal")
			case "--upload-file", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii", "--form", "--form-string", "--json":
				a.add(Medium, "curl sends data to a server", "")
			case "--request":
				m := strings.ToUpper(val(&i, v, has))
				if m != "GET" && m != "HEAD" && m != "OPTIONS" {
					a.add(Medium, "curl sends a state-changing request ("+short(m)+")", "")
				}
			case "--config":
				a.add(Medium, "curl reads options from a config file", "")
			}
			continue
		}
		for j := 1; j < len(t); j++ {
			rest := t[j+1:]
			switch t[j] {
			case 'o', 'D', 'c':
				fileFlag(a, val(&i, rest, rest != ""), "curl saves output")
				j = len(t)
			case 'O', 'J':
				a.add(Medium, "curl saves a download to a file", "Omit -O to print to the terminal")
			case 'T', 'd', 'F':
				a.add(Medium, "curl sends data to a server", "")
				val(&i, rest, rest != "")
				j = len(t)
			case 'X':
				m := strings.ToUpper(val(&i, rest, rest != ""))
				if m != "GET" && m != "HEAD" && m != "OPTIONS" {
					a.add(Medium, "curl sends a state-changing request ("+short(m)+")", "")
				}
				j = len(t)
			case 'K':
				a.add(Medium, "curl reads options from a config file", "")
			}
		}
	}
}

func wgetCheck(c *call, a *acc) {
	args := c.args
	toStdout := false
	for i := 0; i < len(args); i++ {
		t := args[i].text
		if t == "--" {
			break
		}
		if len(t) < 2 || t[0] != '-' {
			continue
		}
		if t[1] == '-' {
			name, v, has := strings.Cut(t, "=")
			switch name {
			case "--spider":
				toStdout = true
			case "--output-document":
				if !has && i+1 < len(args) {
					i++
					v = args[i].text
				}
				if v == "-" || v == "/dev/null" {
					toStdout = true
				} else {
					fileFlag(a, v, "wget saves output")
					toStdout = true
				}
			case "--post-data", "--post-file", "--method", "--body-data", "--body-file":
				a.add(Medium, "wget sends data to a server", "")
			case "--execute":
				a.add(High, "wget --execute changes wget's configuration at run time", "")
			}
			continue
		}
		for j := 1; j < len(t); j++ {
			if t[j] == 'O' {
				v := t[j+1:]
				if v == "" && i+1 < len(args) {
					i++
					v = args[i].text
				}
				if v == "-" || v == "/dev/null" {
					toStdout = true
				} else {
					fileFlag(a, v, "wget saves output")
					toStdout = true
				}
				break
			}
			if t[j] == 'e' {
				a.add(High, "wget -e changes wget's configuration at run time", "")
			}
		}
	}
	if !toStdout {
		a.add(Medium, "wget saves the download to a file", "Use wget -qO- to print to the terminal")
	}
}

var sshOpt = set("-p -i -l -o -F -J -L -R -D -b -c -E -e -m -O -Q -S -W -w -B -I")

func sshCheck(c *call, a *acc) {
	args := c.args
	for _, w := range args {
		l := strings.ToLower(w.text)
		if strings.Contains(l, "proxycommand") || strings.Contains(l, "localcommand") {
			a.add(High, "ssh option runs a local command", "")
		}
	}
	i := 0
	for ; i < len(args); i++ {
		t := args[i].text
		if t == "--" {
			i++
			break
		}
		if len(t) > 1 && t[0] == '-' {
			if sshOpt[t] {
				i++
			}
			continue
		}
		break
	}
	// args[i] is the host; everything after it is the remote command.
	if i+1 >= len(args) {
		return
	}
	rest := args[i+1:]
	if anyDyn(rest) {
		a.add(High, "ssh remote command is built from variables or substitutions", "")
	}
	a.merge(c.s.analyze(joinText(rest), c.depth+1))
}

func rsyncCheck(c *call, a *acc) {
	for _, w := range c.args {
		if strings.HasPrefix(w.text, "--delete") || w.text == "--remove-source-files" {
			a.add(High, "rsync "+short(w.text)+" removes files", "Run with --dry-run first")
		}
	}
}

func ncCheck(c *call, a *acc) {
	if hasFlag(c.args, "ec", "--exec", "--sh-exec", "--lua-exec") {
		a.add(High, c.name+" attaches a program to a network connection", "")
	}
	for _, w := range c.args {
		u := strings.ToUpper(w.text)
		if strings.HasPrefix(u, "EXEC:") || strings.HasPrefix(u, "SYSTEM:") || strings.Contains(u, ",EXEC:") {
			a.add(High, c.name+" attaches a program to a network connection", "")
		}
	}
}

func killCheck(c *call, a *acc) {
	args := c.args
	for _, w := range positional(args, set("-s -n")) {
		if w.text == "1" {
			a.add(Critical, "kill: signals init (PID 1)", "")
		}
	}
	if n := len(args); n >= 2 && args[n-1].text == "-1" && strings.HasPrefix(args[n-2].text, "-") {
		a.add(Critical, "kill: signals every process", "")
	}
}

var criticalProcs = set("sshd ssh systemd init NetworkManager systemd-networkd dbus-daemon login getty sddm gdm lightdm")

func pkillCheck(c *call, a *acc) {
	if c.name == "killall5" {
		return
	}
	for _, w := range positional(c.args, set("-u -g -s -t -P -U -G -n -o -e --signal --user")) {
		if criticalProcs[w.text] {
			a.add(Critical, c.name+": stops a process that provides remote access, networking or the system itself", "")
		}
	}
}

var lockoutUnits = set("ssh sshd NetworkManager networking systemd-networkd network")

func unitRisk(verb, unit string, a *acc) {
	u := strings.TrimSuffix(strings.TrimSuffix(unit, ".service"), ".socket")
	if !lockoutUnits[u] {
		return
	}
	switch verb {
	case "stop", "disable", "mask", "kill", "isolate":
		a.add(Critical, "stops the service that provides remote access or networking ("+short(u)+"), which can lock you out", "")
	case "restart", "reload", "try-restart", "reload-or-restart", "force-reload", "condrestart":
		a.add(High, "restarts the service that provides remote access or networking ("+short(u)+")", "Validate the configuration first (sshd -t) and keep a second session open")
	}
}

func systemctlCheck(c *call, a *acc) {
	pos := positional(c.args, c.rule("systemctl"))
	if len(pos) < 2 {
		return
	}
	for _, u := range pos[1:] {
		unitRisk(pos[0].text, u.text, a)
	}
}

func (c *call) rule(name string) map[string]bool { return rules[name].optArg }

func serviceCheck(c *call, a *acc) {
	pos := positional(c.args, nil)
	if len(pos) >= 2 {
		unitRisk(pos[1].text, pos[0].text, a)
	}
}

func ctlCheck(c *call, a *acc) {
	pos := positional(c.args, set("-H -M -n -o -p -t -s --host --machine --lines --output --property --type --signal"))
	if len(pos) == 0 {
		return
	}
	v := pos[0].text
	switch c.name {
	case "hostnamectl", "timedatectl", "localectl":
		switch v {
		case "status", "show", "list-timezones", "list-locales", "list-keymaps", "list-x11-keymap-models", "list-x11-keymap-layouts", "list-x11-keymap-variants", "list-x11-keymap-options":
			return
		}
	case "busctl":
		switch v {
		case "list", "status", "tree", "introspect", "monitor", "capture", "get-property":
			return
		}
	case "machinectl", "coredumpctl", "networkctl":
		switch v {
		case "list", "status", "show", "list-images", "info", "lldp", "show-image":
			return
		}
	case "resolvectl", "systemd-resolve":
		switch v {
		case "status", "query", "statistics", "show-cache", "show-server-state", "monitor", "service", "openpgp", "tlsa", "log-level":
			return
		}
		a.add(Medium, c.name+": changes resolver state", "")
		return
	default: // loginctl
		if strings.HasPrefix(v, "list-") || strings.HasPrefix(v, "show-") || strings.HasSuffix(v, "-status") || v == "status" {
			return
		}
	}
	a.add(High, c.name+" "+short(v)+": changes system state", "")
}

func iptablesCheck(c *call, a *acc) {
	if hasFlag(c.args, "FX", "--flush", "--delete-chain") {
		a.add(Critical, c.name+": flushes firewall rules (can open the host or lock out remote access)", "List rules with -L first and save them with iptables-save")
	} else if hasFlag(c.args, "P", "--policy") {
		a.add(Critical, c.name+": changes a default chain policy (can lock out remote access)", "")
	} else if hasFlag(c.args, "ADIRNE", "--append", "--delete", "--insert", "--replace", "--new-chain", "--rename-chain") {
		a.add(High, c.name+": changes firewall rules", "")
	}
}

func nftCheck(c *call, a *acc) {
	for _, w := range c.args {
		if w.text == "flush" {
			a.add(Critical, "nft: flushes firewall rules (can open the host or lock out remote access)", "")
		}
	}
	pos := positional(c.args, set("-f -i"))
	if hasFlag(c.args, "f") {
		a.add(High, "nft: loads a rule file", "")
	}
	if len(pos) > 0 && pos[0].text != "list" && pos[0].text != "monitor" {
		a.add(High, "nft: changes firewall rules", "")
	}
}

func ipCheck(c *call, a *acc) {
	pos := positional(c.args, set("-n -b -batch -rc -netns -l -loops -force"))
	if len(pos) < 2 {
		return
	}
	switch pos[1].text {
	case "show", "list", "ls", "lst", "get", "monitor", "help", "save", "sh", "s":
		return
	}
	a.add(High, "ip "+short(pos[0].text)+" "+short(pos[1].text)+": changes network configuration (can cut the connection)", "")
}

func nmcliCheck(c *call, a *acc) {
	pos := positional(c.args, set("-f -t -m -c -p -w -a -e -s --fields --mode --colors --wait"))
	if len(pos) < 2 {
		return
	}
	switch pos[1].text {
	case "show", "status", "list", "lldp", "monitor", "help", "permissions":
		return
	}
	a.add(High, "nmcli: changes network configuration (can cut the connection)", "")
}

func partedCheck(c *call, a *acc) {
	pos := positional(c.args, set("-s -a"))
	for _, w := range pos {
		switch w.text {
		case "mklabel", "mktable", "mkpart", "rm", "resizepart", "name", "set", "move", "rescue", "mkfs", "resize", "toggle":
			a.add(Critical, "parted: edits a partition table", "")
			return
		}
	}
	if hasFlag(c.args, "l", "--list") {
		return
	}
	for _, w := range pos {
		if w.text == "print" || w.text == "p" || w.text == "unit" {
			return
		}
	}
	a.add(Critical, "parted: may edit a partition table", "")
}

func pacmanCheck(c *call, a *acc) {
	if len(c.args) == 0 {
		return
	}
	t := c.args[0].text
	switch {
	case strings.HasPrefix(t, "--remove"):
		a.add(High, "pacman: removes packages", "")
	case strings.HasPrefix(t, "--query") || strings.HasPrefix(t, "--files") || strings.HasPrefix(t, "--version"):
	case strings.HasPrefix(t, "--"):
		a.add(Medium, "pacman: changes installed packages", "")
	case strings.HasPrefix(t, "-") && strings.Contains(t, "R"):
		a.add(High, "pacman: removes packages", "")
	case strings.HasPrefix(t, "-") && (strings.Contains(t, "Q") || strings.Contains(t, "F") || strings.Contains(t, "V") || strings.Contains(t, "h")):
	case strings.HasPrefix(t, "-S") && (strings.Contains(t, "s") || strings.Contains(t, "i") || strings.Contains(t, "l") || strings.Contains(t, "g")) &&
		!strings.Contains(t, "y") && !strings.Contains(t, "u"):
	default:
		a.add(Medium, "pacman: changes installed packages", "")
	}
}

func dpkgCheck(c *call, a *acc) {
	switch {
	case hasFlag(c.args, "rP", "--remove", "--purge"):
		a.add(High, "dpkg: removes packages", "")
	case hasFlag(c.args, "ixa", "--install", "--unpack", "--configure", "--triggers-only"):
		a.add(Medium, "dpkg: installs packages", "")
	}
}

func rpmCheck(c *call, a *acc) {
	if len(c.args) == 0 {
		return
	}
	t := c.args[0].text
	switch {
	case t == "--erase" || (!strings.HasPrefix(t, "--") && strings.HasPrefix(t, "-") && strings.Contains(t, "e") && !strings.Contains(t, "q")):
		a.add(High, "rpm: removes packages", "")
	case t == "--query" || t == "--verify" || t == "--version" || (!strings.HasPrefix(t, "--") && (strings.Contains(t, "q") || strings.Contains(t, "V"))):
	default:
		a.add(Medium, "rpm: changes installed packages", "")
	}
}

func awsCheck(c *call, a *acc) {
	pos := positional(c.args, set("--profile --region --output --query --endpoint-url"))
	if len(pos) < 2 {
		if len(pos) == 1 && pos[0].text == "configure" {
			a.add(High, "aws configure changes stored credentials", "")
		}
		return
	}
	v := pos[1].text
	for _, pre := range []string{"describe", "list", "get-", "ls", "head", "wait", "lookup", "batch-get", "search"} {
		if strings.HasPrefix(v, pre) {
			return
		}
	}
	a.add(High, "aws "+short(pos[0].text)+" "+short(v)+": changes cloud resources", "")
}
