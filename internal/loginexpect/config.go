package loginexpect

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Limits keep a saved configuration small and a runaway prompt from holding a
// session forever.
const (
	// DefaultTimeoutSeconds is the wait of a rule that names none.
	DefaultTimeoutSeconds = 30
	// MaxTimeoutSeconds is the longest wait a rule may ask for.
	MaxTimeoutSeconds = 3600
	// MaxDelayMilliseconds is the longest wait a rule may ask for between a
	// matched prompt and its reply. It mirrors MaxTimeoutSeconds (one hour) and
	// keeps the value far below any overflow of a time.Duration.
	MaxDelayMilliseconds = 3600 * 1000
	// MaxDelay is MaxDelayMilliseconds as a Duration.
	MaxDelay = time.Duration(MaxDelayMilliseconds) * time.Millisecond
	// MaxSteps bounds one host's rules.
	MaxSteps = 64
	// MaxExpect and MaxSend bound one rule's texts. A prompt longer than this is
	// not a prompt a person would type by hand.
	MaxExpect = 1024
	MaxSend   = 4096
)

// Step is one ordered Expect/Send rule: wait for Expect in the terminal output,
// then send Send, optionally followed by Enter. A sensitive step carries no
// saved response; the value is asked for at runtime and never stored.
type Step struct {
	ID      string
	Expect  string
	Send    string
	Timeout time.Duration
	// Delay is paused after Expect matches and before Send is written. Zero
	// sends at once, which is what every rule saved before this field did.
	Delay       time.Duration
	AppendEnter bool
	Sensitive   bool
}

// Config is a host's login automation: whether it runs, and its rules in order.
type Config struct {
	Enabled bool
	Steps   []Step
}

// DecodeText decodes terminal escapes once so a rule can wait for a carriage
// return or send a control character without embedding one in the form. Known
// escapes are \r \n \t \e \\ and \xNN; anything else is left as typed, so a
// literal backslash is not lost.
func DecodeText(text string) string {
	if !strings.ContainsRune(text, '\\') {
		return text
	}
	var out strings.Builder
	out.Grow(len(text))
	for index := 0; index < len(text); index++ {
		if text[index] != '\\' || index+1 == len(text) {
			out.WriteByte(text[index])
			continue
		}
		next := text[index+1]
		switch next {
		case 'r':
			out.WriteByte('\r')
			index++
		case 'n':
			out.WriteByte('\n')
			index++
		case 't':
			out.WriteByte('\t')
			index++
		case 'e':
			out.WriteByte(0x1b)
			index++
		case '\\':
			out.WriteByte('\\')
			index++
		case 'x':
			if index+3 < len(text) {
				if value, err := strconv.ParseUint(text[index+2:index+4], 16, 8); err == nil {
					out.WriteByte(byte(value))
					index += 3
					continue
				}
			}
			out.WriteByte(text[index])
		default:
			// An unknown escape stays literal, backslash included.
			out.WriteByte(text[index])
		}
	}
	return out.String()
}

// DelayFromMilliseconds converts a saved whole-millisecond count to a Duration.
// It clamps negative and out-of-range values before multiplying, so a corrupt
// or hostile number cannot overflow time.Duration.
func DelayFromMilliseconds(milliseconds int) time.Duration {
	if milliseconds <= 0 {
		return 0
	}
	if milliseconds > MaxDelayMilliseconds {
		milliseconds = MaxDelayMilliseconds
	}
	return time.Duration(milliseconds) * time.Millisecond
}

// DelayMilliseconds converts a Duration back to whole milliseconds, clamped the
// same way, so the saved form and the editor show the value the runner uses.
func DelayMilliseconds(delay time.Duration) int {
	if delay <= 0 {
		return 0
	}
	if delay > MaxDelay {
		return MaxDelayMilliseconds
	}
	return int(delay / time.Millisecond)
}

// Normalize returns a copy of cfg that is safe to run: timeouts are within the
// supported range, texts are bounded, every rule has a stable unique id, and a
// sensitive rule never carries a saved response. Rules that contain nothing at
// all are dropped, since they would neither wait nor send.
func Normalize(cfg Config) Config {
	steps := make([]Step, 0, len(cfg.Steps))
	ids := make(map[string]struct{}, len(cfg.Steps))
	for index, step := range cfg.Steps {
		if len(steps) == MaxSteps {
			break
		}
		if step.Sensitive {
			step.Send = ""
		}
		step.Expect = truncate(step.Expect, MaxExpect)
		step.Send = truncate(step.Send, MaxSend)
		if step.Expect == "" && step.Send == "" && !step.Sensitive {
			continue
		}
		if step.Timeout < time.Second {
			step.Timeout = DefaultTimeoutSeconds * time.Second
		}
		if step.Timeout > MaxTimeoutSeconds*time.Second {
			step.Timeout = MaxTimeoutSeconds * time.Second
		}
		if step.Delay < 0 {
			step.Delay = 0
		}
		if step.Delay > MaxDelay {
			step.Delay = MaxDelay
		}
		id := strings.TrimSpace(step.ID)
		if id == "" {
			id = fmt.Sprintf("step-%d", index+1)
		}
		unique := id
		for number := 2; ; number++ {
			if _, taken := ids[unique]; !taken {
				break
			}
			unique = fmt.Sprintf("%s-%d", id, number)
		}
		step.ID = unique
		ids[unique] = struct{}{}
		steps = append(steps, step)
	}
	return Config{Enabled: cfg.Enabled, Steps: steps}
}

func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	// Cut on a rune boundary where possible so a multi-byte character is kept.
	cut := limit
	for cut > 0 && text[cut]&0xC0 == 0x80 {
		cut--
	}
	return text[:cut]
}

// Clone returns a deep copy, so a draft edited in a form cannot change the host
// it was loaded from.
func (cfg Config) Clone() Config {
	steps := make([]Step, len(cfg.Steps))
	copy(steps, cfg.Steps)
	return Config{Enabled: cfg.Enabled, Steps: steps}
}

// Active reports whether the configuration would run anything.
func (cfg Config) Active() bool { return cfg.Enabled && len(cfg.Steps) > 0 }
