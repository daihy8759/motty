package workbench

import (
	"time"

	"motty/internal/loginexpect"
)

// savedLoginExpect is how a host's login automation travels in the state file
// and in a host catalog. It is optional: a host that never used it keeps the
// field absent, and an older file simply has none.
type savedLoginExpect struct {
	Enabled bool                   `json:"enabled"`
	Steps   []savedLoginExpectStep `json:"steps,omitempty"`
}

// savedLoginExpectStep is one rule as saved. AppendEnter is a pointer so the
// form's default (true) survives a round trip even though JSON's zero value is
// false. A sensitive rule never carries Send.
type savedLoginExpectStep struct {
	ID             string `json:"id,omitempty"`
	Expect         string `json:"expect,omitempty"`
	Send           string `json:"send,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	// DelayMilliseconds is paused after Expect matches and before Send. It is
	// absent for every rule saved before the field existed, and 0 sends at once.
	DelayMilliseconds int   `json:"delay_ms,omitempty"`
	AppendEnter       *bool `json:"append_enter,omitempty"`
	Sensitive         bool  `json:"sensitive,omitempty"`
	// CommandMode sends a bare ":" before the reply, entering a menu shell's
	// command line. Absent on every rule saved before this field existed.
	CommandMode bool `json:"command_mode,omitempty"`
}

// encodeLoginExpect turns a host's configuration into its saved form, or nil
// when there is nothing to keep. A sensitive rule's response is never written.
func encodeLoginExpect(config *loginexpect.Config) *savedLoginExpect {
	if config == nil {
		return nil
	}
	cfg := loginexpect.Normalize(*config)
	if !cfg.Enabled && len(cfg.Steps) == 0 {
		return nil
	}
	out := &savedLoginExpect{Enabled: cfg.Enabled}
	for _, step := range cfg.Steps {
		seconds := int(step.Timeout / time.Second)
		if seconds <= 0 {
			seconds = loginexpect.DefaultTimeoutSeconds
		}
		enter := step.AppendEnter
		saved := savedLoginExpectStep{
			ID: step.ID, Expect: step.Expect, TimeoutSeconds: seconds,
			DelayMilliseconds: loginexpect.DelayMilliseconds(step.Delay),
			AppendEnter:       &enter, Sensitive: step.Sensitive,
			CommandMode: step.CommandMode,
		}
		if !step.Sensitive {
			saved.Send = step.Send
		}
		out.Steps = append(out.Steps, saved)
	}
	return out
}

// decodeLoginExpect reads a saved configuration, dropping what cannot be used
// today rather than failing the whole host. A missing entry is no automation.
func decodeLoginExpect(entry *savedLoginExpect) *loginexpect.Config {
	if entry == nil {
		return nil
	}
	steps := make([]loginexpect.Step, 0, len(entry.Steps))
	for _, saved := range entry.Steps {
		appendEnter := true
		if saved.AppendEnter != nil {
			appendEnter = *saved.AppendEnter
		}
		timeout := time.Duration(saved.TimeoutSeconds) * time.Second
		if timeout < time.Second {
			timeout = loginexpect.DefaultTimeoutSeconds * time.Second
		}
		send := saved.Send
		if saved.Sensitive {
			send = ""
		}
		steps = append(steps, loginexpect.Step{
			ID: saved.ID, Expect: saved.Expect, Send: send, Timeout: timeout,
			Delay:       loginexpect.DelayFromMilliseconds(saved.DelayMilliseconds),
			AppendEnter: appendEnter, Sensitive: saved.Sensitive,
			CommandMode: saved.CommandMode,
		})
	}
	cfg := loginexpect.Normalize(loginexpect.Config{Enabled: entry.Enabled, Steps: steps})
	if !cfg.Enabled && len(cfg.Steps) == 0 {
		return nil
	}
	return &cfg
}

// sameSavedLoginExpect reports whether two saved configurations are identical,
// so an edit elsewhere does not rewrite a host record that did not change.
func sameSavedLoginExpect(left, right *savedLoginExpect) bool {
	if left == nil || right == nil {
		return left == right
	}
	if left.Enabled != right.Enabled || len(left.Steps) != len(right.Steps) {
		return false
	}
	for index := range left.Steps {
		a, b := left.Steps[index], right.Steps[index]
		if a.ID != b.ID || a.Expect != b.Expect || a.Send != b.Send ||
			a.TimeoutSeconds != b.TimeoutSeconds || a.Sensitive != b.Sensitive ||
			a.DelayMilliseconds != b.DelayMilliseconds || a.CommandMode != b.CommandMode {
			return false
		}
		if (a.AppendEnter == nil) != (b.AppendEnter == nil) {
			return false
		}
		if a.AppendEnter != nil && *a.AppendEnter != *b.AppendEnter {
			return false
		}
	}
	return true
}
