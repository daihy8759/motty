package sshconn

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// ErrTransportClosed reports that a channel could not be opened because the SSH
// transport had already shut down. x/crypto/ssh surfaces this in a misleading
// way: when the mux loop exits while a channel open is in flight, the channel's
// internal message channel is closed and the open call reads a nil message, so
// the library reports
//
//	ssh: unexpected packet in response to channel open: <nil>
//
// That "<nil>" is not a packet the server sent; it is the client state machine
// observing a transport that is already gone (a well-formed or malformed
// disconnect, a keepalive timeout, or a socket reset). Treating it as a live
// protocol error made Motty reuse the dead client and report the wrong cause.
var ErrTransportClosed = errors.New("sshconn: the SSH connection closed before the channel could be opened")

// transportClosedError classifies the mux's nil-packet channel-open failure as
// a lost connection. It satisfies errors.Is(ErrDisconnected) so cleanup, the UI
// and reconnect handling treat it like any other unexpected end, while callers
// can branch on ErrTransportClosed to stop immediately instead of reusing the
// dead transport. The library error stays reachable for diagnostics.
type transportClosedError struct {
	cause error
}

func (err *transportClosedError) Error() string {
	if err.cause == nil {
		return ErrTransportClosed.Error()
	}
	return fmt.Sprintf("%s: %v", ErrTransportClosed.Error(), err.cause)
}

func (err *transportClosedError) Unwrap() error { return err.cause }

func (err *transportClosedError) Is(target error) bool {
	return target == ErrTransportClosed || target == ErrDisconnected
}

// ErrMalformedDisconnect reports that the peer ended the SSH transport with an
// SSH_MSG_DISCONNECT packet that golang.org/x/crypto/ssh could not decode.
//
// RFC 4253 section 11.1 defines the packet as a reason code, a description and
// a language tag. Some servers, notably several network appliances, omit the
// language tag or cut the packet short. x/crypto/ssh decodes every field
// strictly, so it returns a bare "unmarshal error" and loses the reason and
// description the server did send. The transport is already unusable at that
// point, but the user still deserves to know why instead of seeing an
// implementation detail from the library.
var ErrMalformedDisconnect = errors.New("sshconn: the server closed the connection with a malformed SSH disconnect message")

// malformedDisconnectError classifies a transport decode failure as both a
// malformed disconnect and a normal disconnect. Existing cleanup, UI and
// diagnostics paths keep treating it as a disconnect, while callers can branch
// on ErrMalformedDisconnect to avoid retrying a protocol error that will not
// heal. The original library error remains reachable with errors.Unwrap and is
// quoted in the user-facing text, so the decode failure is explained rather
// than swallowed.
type malformedDisconnectError struct {
	cause error
}

func (err *malformedDisconnectError) Error() string {
	const detail = "a required field is missing or truncated"
	if err.cause == nil {
		return fmt.Sprintf("%s (%s)", ErrMalformedDisconnect.Error(), detail)
	}
	return fmt.Sprintf("%s (%s): %v", ErrMalformedDisconnect.Error(), detail, err.cause)
}

func (err *malformedDisconnectError) Unwrap() error { return err.cause }

func (err *malformedDisconnectError) Is(target error) bool {
	return target == ErrMalformedDisconnect || target == ErrDisconnected
}

// malformedDisconnect reports whether err is x/crypto/ssh's Unmarshal failure
// for an SSH_MSG_DISCONNECT packet. The packet has already passed decryption
// and MAC verification when Unmarshal runs, so this is a real peer protocol
// error, not a local read or network corruption problem. Only the library's
// field-specific decode errors carry the message type; a plain "short read"
// could belong to any packet and is deliberately not guessed at here.
func malformedDisconnect(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "unmarshal error for field ") &&
		strings.Contains(message, " of type disconnectMsg")
}

// deadMuxChannelOpen reports whether err is the nil-packet channel-open failure
// x/crypto/ssh returns when the mux loop has already exited. The library only
// produces a nil message here when it closed a pending channel's message queue,
// so this is always a transport that is already gone, never a real reply.
func deadMuxChannelOpen(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "unexpected packet in response to channel open: <nil>")
}

// normalizeServerError turns an undecodable SSH disconnect, or a channel open
// that lost the mux underneath it, into a stable, actionable error. Every other
// error is returned unchanged: in particular a well-formed disconnect keeps the
// server's reason and description, and authentication, host-key and
// cancellation semantics are untouched.
func normalizeServerError(err error) error {
	if err == nil || errors.Is(err, ErrMalformedDisconnect) || errors.Is(err, ErrTransportClosed) {
		return err
	}
	if malformedDisconnect(err) {
		return &malformedDisconnectError{cause: err}
	}
	if deadMuxChannelOpen(err) {
		return &transportClosedError{cause: err}
	}
	return err
}

// transportGone reports that err means the SSH transport itself is finished,
// not that a request on a live connection was refused. Optional follow-ups
// such as retrying a shell without its integration wrapper are pointless once
// this is true: the retry cannot reach the server and would only hide the
// original failure behind a second, less specific error.
func transportGone(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, ErrCanceled) || errors.Is(err, ErrMalformedDisconnect) ||
		errors.Is(err, ErrTransportClosed) {
		return true
	}
	message := strings.ToLower(err.Error())
	return deadMuxChannelOpen(err) ||
		strings.Contains(message, "mux client closed") ||
		strings.Contains(message, "use of closed network connection") ||
		strings.Contains(message, "connection reset by peer") ||
		strings.Contains(message, "broken pipe")
}
