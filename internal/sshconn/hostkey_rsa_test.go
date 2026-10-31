package sshconn

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// rsaOnlyHostKey makes the test server present an RSA host key that can only
// sign with SHA-1 "ssh-rsa", the way an old appliance does. A plain RSA signer
// would also advertise the modern rsa-sha2 variants, so the signing algorithms
// are restricted explicitly.
func rsaOnlyHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	base, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	algorithm, ok := base.(ssh.AlgorithmSigner)
	if !ok {
		t.Fatalf("the RSA signer does not support choosing an algorithm: %T", base)
	}
	signer, err := ssh.NewSignerWithAlgorithms(algorithm, []string{ssh.KeyAlgoRSA})
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// A host already on file under an RSA key used to offer only rsa-sha2-512 and
// rsa-sha2-256, so an old server whose only host-key algorithm is ssh-rsa
// failed with "no common algorithm for host key". The key itself is still
// trusted; only the signature algorithm needs the SHA-1 fallback.
func TestAKnownRSAHostReachesAServerThatOnlyOffersSSHRSA(t *testing.T) {
	server := startServer(t, func(s *testServer) {
		s.password = "pw"
		s.hostKey = rsaOnlyHostKey(t)
	})
	// Both connections read the same known-hosts file, so the second finds the
	// key the first saved.
	path := filepath.Join(t.TempDir(), "known_hosts")
	useKnown := func(config *Config) { config.KnownHostsPath = path }

	first := dial(t, server, useKnown)
	first.phase(PhaseHostKeyPrompt)
	first.conn.TrustHostKey(true)
	first.phase(PhasePasswordPrompt)
	first.conn.SubmitPassword("pw")
	first.phase(PhaseConnected)

	second := dial(t, server, useKnown)
	status := second.until("the known host to be ready to authenticate", func(s Status) bool {
		return s.Phase == PhasePasswordPrompt || s.Phase == PhaseFailed || s.Phase == PhaseHostKeyPrompt
	})
	if status.Phase != PhasePasswordPrompt {
		t.Fatalf("second connection: phase %d, err %v", status.Phase, status.Err)
	}
	second.conn.SubmitPassword("pw")
	connected := second.phase(PhaseConnected)
	if connected.Negotiated.HostKey != ssh.KeyAlgoRSA {
		t.Fatalf("negotiated host key = %q, want %q", connected.Negotiated.HostKey, ssh.KeyAlgoRSA)
	}
}

// A modern server with an RSA host key must still be checked with SHA-2: the
// SHA-1 fallback is only for servers that cannot do better.
func TestAKnownRSAHostStillPrefersTheSHA2Signature(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	server := startServer(t, func(s *testServer) {
		s.password = "pw"
		s.hostKey = signer
	})
	path := filepath.Join(t.TempDir(), "known_hosts")
	useKnown := func(config *Config) { config.KnownHostsPath = path }

	first := dial(t, server, useKnown)
	first.phase(PhaseHostKeyPrompt)
	first.conn.TrustHostKey(true)
	first.phase(PhasePasswordPrompt)
	first.conn.SubmitPassword("pw")
	first.phase(PhaseConnected)

	second := dial(t, server, useKnown)
	second.until("the known host to be ready to authenticate", func(s Status) bool {
		return s.Phase == PhasePasswordPrompt || s.Phase == PhaseFailed || s.Phase == PhaseHostKeyPrompt
	})
	second.conn.SubmitPassword("pw")
	connected := second.phase(PhaseConnected)
	if connected.Negotiated.HostKey != ssh.KeyAlgoRSASHA256 && connected.Negotiated.HostKey != ssh.KeyAlgoRSASHA512 {
		t.Fatalf("negotiated host key = %q, want a rsa-sha2 variant", connected.Negotiated.HostKey)
	}
	if weak := connected.Negotiated.Weak(); len(weak) != 0 {
		t.Fatalf("a modern connection reported weak algorithms: %v", weak)
	}
}

func TestAKnownRSAOnlyJumpHostStaysReachable(t *testing.T) {
	target := startServer(t, func(s *testServer) { s.password = "target-pw" })
	targetHost, targetPort := target.host()
	targetAddress := net.JoinHostPort(targetHost, itoa(targetPort))
	jump := startServer(t, func(s *testServer) {
		s.password = "jump-pw"
		s.hostKey = rsaOnlyHostKey(t)
		s.direct = targetAddress
	})
	jumpHost, jumpPort := jump.host()
	path := filepath.Join(t.TempDir(), "known_hosts")
	useKnown := func(config *Config) {
		config.KnownHostsPath = path
		config.ProxyJumps = []Endpoint{{Host: jumpHost, Port: jumpPort, User: "bastion"}}
	}

	first := dial(t, target, useKnown)
	first.phase(PhaseHostKeyPrompt) // the jump host
	first.conn.TrustHostKey(true)
	first.phase(PhasePasswordPrompt)
	first.conn.SubmitPassword("jump-pw")
	first.phase(PhaseHostKeyPrompt) // the target
	first.conn.TrustHostKey(true)
	first.phase(PhasePasswordPrompt)
	first.conn.SubmitPassword("target-pw")
	first.phase(PhaseConnected)

	second := dial(t, target, useKnown)
	jumpPassword := second.until("the known jump host to be ready to authenticate", func(s Status) bool {
		return (s.Phase == PhasePasswordPrompt && s.EndpointRole == EndpointProxyJump) || s.Phase == PhaseFailed
	})
	if jumpPassword.Phase != PhasePasswordPrompt {
		t.Fatalf("known jump host: phase %d, err %v", jumpPassword.Phase, jumpPassword.Err)
	}
	second.conn.SubmitPassword("jump-pw")
	targetPassword := second.until("the known target to be ready to authenticate", func(s Status) bool {
		return (s.Phase == PhasePasswordPrompt && s.EndpointRole == EndpointTarget) || s.Phase == PhaseFailed
	})
	if targetPassword.Phase != PhasePasswordPrompt {
		t.Fatalf("known target: phase %d, err %v", targetPassword.Phase, targetPassword.Err)
	}
	second.conn.SubmitPassword("target-pw")
	second.phase(PhaseConnected)
}

// A Custom list that names host-key algorithms sharing nothing with the key on
// file must fail before the handshake: it must neither fall back to the trusted
// RSA key (which would now offer ssh-rsa again) nor be replaced with nil, which
// would let the library defaults through.
func TestACustomListWithoutTheKnownKeyTypeIsRefusedBeforeTheHandshake(t *testing.T) {
	server := startServer(t, func(s *testServer) {
		s.password = "pw"
		s.hostKey = rsaOnlyHostKey(t)
	})
	host, port := server.host()
	path := filepath.Join(t.TempDir(), "known_hosts")
	custom, err := ParseAlgorithms(ssh.KeyAlgoED25519)
	if err != nil {
		t.Fatal(err)
	}

	first := dial(t, server, func(config *Config) { config.KnownHostsPath = path })
	first.phase(PhaseHostKeyPrompt)
	first.conn.TrustHostKey(true)
	first.phase(PhasePasswordPrompt)
	first.conn.SubmitPassword("pw")
	first.phase(PhaseConnected)

	second := dial(t, server, func(config *Config) {
		config.KnownHostsPath = path
		config.Algorithms = map[string]Algorithms{EndpointKey(host, port): custom}
	})
	status := second.until("the custom list to be refused", func(s Status) bool {
		return s.Phase == PhaseFailed || s.Phase == PhaseHostKeyPrompt || s.Phase == PhasePasswordPrompt
	})
	if status.Phase != PhaseFailed {
		t.Fatalf("custom list without the trusted key type connected or prompted: phase %d, err %v", status.Phase, status.Err)
	}
	var conflict *HostKeyAlgorithmError
	if !errors.As(status.Err, &conflict) {
		t.Fatalf("error = %v, want a HostKeyAlgorithmError", status.Err)
	}
	if offered := server.offered(); len(offered) != 1 {
		t.Fatalf("the refused connection reached authentication: %v", offered)
	}
}

// A Custom list of only SHA-2 RSA signatures must not be widened with ssh-rsa:
// a server that can only sign with SHA-1 is refused instead of connected.
func TestACustomRSAOnlyListRefusesAnSSHRSAOnlyServer(t *testing.T) {
	server := startServer(t, func(s *testServer) {
		s.password = "pw"
		s.hostKey = rsaOnlyHostKey(t)
	})
	host, port := server.host()
	path := filepath.Join(t.TempDir(), "known_hosts")
	custom, err := ParseAlgorithms(ssh.KeyAlgoRSASHA256 + "," + ssh.KeyAlgoRSASHA512)
	if err != nil {
		t.Fatal(err)
	}

	first := dial(t, server, func(config *Config) { config.KnownHostsPath = path })
	first.phase(PhaseHostKeyPrompt)
	first.conn.TrustHostKey(true)
	first.phase(PhasePasswordPrompt)
	first.conn.SubmitPassword("pw")
	first.phase(PhaseConnected)

	second := dial(t, server, func(config *Config) {
		config.KnownHostsPath = path
		config.Algorithms = map[string]Algorithms{EndpointKey(host, port): custom}
	})
	status := second.until("the SHA-2-only list to be refused", func(s Status) bool {
		return s.Phase == PhaseFailed || s.Phase == PhaseHostKeyPrompt || s.Phase == PhasePasswordPrompt
	})
	if status.Phase != PhaseFailed {
		t.Fatalf("SHA-2-only custom list reached an ssh-rsa-only server: phase %d, err %v", status.Phase, status.Err)
	}
	var conflict *HostKeyAlgorithmError
	if errors.As(status.Err, &conflict) {
		t.Fatalf("overlap should fail at negotiation, not pre-handshake: %v", status.Err)
	}
	if status.Err == nil || !strings.Contains(status.Err.Error(), "no common algorithm for host key") {
		t.Fatalf("error = %v, want a host-key negotiation failure", status.Err)
	}
	if offered := server.offered(); len(offered) != 1 {
		t.Fatalf("the refused connection reached authentication: %v", offered)
	}
}
