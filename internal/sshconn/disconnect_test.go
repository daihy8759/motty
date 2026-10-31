package sshconn

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// disconnectMsg is the RFC 4253 section 11.1 packet shape. It deliberately
// uses the same type name x/crypto/ssh does, so a test can feed it malformed
// bytes and get the same "of type disconnectMsg" Unmarshal error the library
// gives Motty.
type disconnectMsg struct {
	Reason   uint32 `sshtype:"1"`
	Message  string
	Language string
}

func appendUint32(dst []byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return append(dst, encoded[:]...)
}

func appendSSHString(dst []byte, value string) []byte {
	dst = appendUint32(dst, uint32(len(value)))
	return append(dst, value...)
}

func TestNormalizeMalformedDisconnect(t *testing.T) {
	// Valid prefix (reason and description) with the mandatory language tag
	// omitted: exactly the packet shape that produces
	// "unmarshal error for field Language of type disconnectMsg".
	missingLanguage := ssh.Marshal(struct {
		Reason  uint32 `sshtype:"1"`
		Message string
	}{Reason: 11, Message: "administratively prohibited"})

	// A description length that reaches past the end of the packet. This is a
	// truncated packet that fails while decoding Message instead.
	truncatedMessage := appendUint32([]byte{1}, 11)
	truncatedMessage = appendUint32(truncatedMessage, 40)
	truncatedMessage = append(truncatedMessage, 'b', 'y')

	for _, test := range []struct {
		name    string
		payload []byte
		field   string
	}{
		{"missing language", missingLanguage, "Language"},
		{"truncated message", truncatedMessage, "Message"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var msg disconnectMsg
			raw := ssh.Unmarshal(test.payload, &msg)
			if raw == nil {
				t.Fatal("malformed disconnect decoded without an error")
			}
			if !strings.Contains(raw.Error(), "unmarshal error for field "+test.field) {
				t.Fatalf("library error = %v, want field %s", raw, test.field)
			}

			err := normalizeServerError(raw)
			if !errors.Is(err, ErrMalformedDisconnect) {
				t.Fatalf("errors.Is(%v, ErrMalformedDisconnect) = false", err)
			}
			if !errors.Is(err, ErrDisconnected) {
				t.Fatalf("malformed disconnect lost its disconnect classification: %v", err)
			}
			if !strings.Contains(err.Error(), raw.Error()) {
				t.Fatalf("user-facing error %q does not quote the library error %q", err, raw)
			}
			if errors.Unwrap(err) == nil {
				t.Fatal("the original decode error is no longer reachable")
			}
			if again := normalizeServerError(err); again != err {
				t.Fatalf("normalization is not idempotent: %v != %v", again, err)
			}
		})
	}
}

func TestNormalizeLeavesOtherErrorsAlone(t *testing.T) {
	for _, err := range []error{
		nil,
		errors.New("ssh: disconnect, reason 11: \"administratively prohibited\""),
		errors.New("ssh: short read"),
		errors.New("connection refused"),
	} {
		if got := normalizeServerError(err); got != err {
			t.Errorf("normalizeServerError(%v) = %v, want unchanged", err, got)
		}
	}
}

func TestTransportGoneRecognisesDeadConnections(t *testing.T) {
	for _, err := range []error{
		io.EOF,
		net.ErrClosed,
		ErrCanceled,
		ErrMalformedDisconnect,
		errors.New("ssh: mux client closed"),
		errors.New("write tcp 127.0.0.1:22: use of closed network connection"),
		errors.New("read tcp 127.0.0.1:22: connection reset by peer"),
	} {
		if !transportGone(err) {
			t.Errorf("transportGone(%v) = false, want true", err)
		}
	}
	for _, err := range []error{
		nil,
		errors.New("ssh: command \"/bin/bash\" failed"),
		errors.New("pty refused"),
	} {
		if transportGone(err) {
			t.Errorf("transportGone(%v) = true, want false", err)
		}
	}
}

// malformedDisconnectPacket builds one unencrypted SSH binary packet carrying
// SSH_MSG_DISCONNECT with no language tag. Before key exchange the wire format
// has no MAC, so a local test server can send it without any SSH library
// internals; everything after the packet header is padded to the 8-byte
// cipher block size.
func malformedDisconnectPacket(reason uint32, message string) []byte {
	payload := []byte{1} // SSH_MSG_DISCONNECT
	payload = appendUint32(payload, reason)
	payload = appendSSHString(payload, message)
	// Deliberately no language string.

	padding := 4
	for (4+1+len(payload)+padding)%8 != 0 {
		padding++
	}
	length := 1 + len(payload) + padding
	packet := make([]byte, 4+length)
	binary.BigEndian.PutUint32(packet[:4], uint32(length))
	packet[4] = byte(padding)
	copy(packet[5:], payload)
	return packet
}

func TestMalformedDisconnectFromServerIsReportedAndReleased(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	var active atomic.Int32
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		for {
			socket, err := listener.Accept()
			if err != nil {
				return
			}
			active.Add(1)
			go func(socket net.Conn) {
				defer active.Add(-1)
				defer socket.Close()
				// Version exchange first, then the malformed disconnect. The
				// client still sends its own version and KEXINIT; drain them so
				// the write side does not block.
				_, _ = socket.Write([]byte("SSH-2.0-MalformedDisconnect\r\n"))
				_, _ = socket.Write(malformedDisconnectPacket(11, "administratively prohibited"))
				_, _ = io.Copy(io.Discard, socket)
			}(socket)
		}
	}()

	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	conn := Dial(Config{
		Host:           host,
		Port:           uint16(port),
		User:           "tester",
		KnownHostsPath: filepath.Join(t.TempDir(), "motty", "known_hosts"),
		IdentityFiles:  []string{},
	})
	defer conn.Close()

	deadline := time.After(10 * time.Second)
	for {
		status := conn.Status()
		if status.Phase == PhaseFailed || status.Phase == PhaseClosed {
			if status.Phase != PhaseFailed {
				t.Fatalf("phase = %v, want failed", status.Phase)
			}
			if status.Err == nil {
				t.Fatal("no error recorded for a malformed disconnect")
			}
			if !errors.Is(status.Err, ErrMalformedDisconnect) {
				t.Fatalf("status error = %v, want ErrMalformedDisconnect", status.Err)
			}
			if !errors.Is(status.Err, ErrDisconnected) {
				t.Fatalf("status error lost ErrDisconnected: %v", status.Err)
			}
			if !strings.Contains(status.Err.Error(), "unmarshal error for field Language of type disconnectMsg") {
				t.Fatalf("status error hides the decode failure: %v", status.Err)
			}
			if conn.Client() != nil {
				t.Fatal("a failed handshake left a client behind")
			}
			break
		}
		select {
		case <-conn.Done():
		case <-deadline:
			t.Fatalf("timed out waiting for the malformed disconnect; last status %+v", conn.Status())
		case <-time.After(10 * time.Millisecond):
		}
	}

	// The transport goroutine owns the socket and closes it on a failed
	// handshake; the listener-side handler must then exit, leaving no
	// connection behind.
	select {
	case <-conn.Done():
	case <-deadline:
		t.Fatal("connection goroutine did not finish")
	}
	for active.Load() != 0 {
		select {
		case <-deadline:
			t.Fatalf("%d server-side connections still open", active.Load())
		case <-time.After(10 * time.Millisecond):
		}
	}
}
