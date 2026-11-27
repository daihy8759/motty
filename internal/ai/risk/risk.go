// Package risk classifies shell command text that an AI assistant wants to run
// on a remote POSIX shell (bash, zsh, sh) and turns the result into an approval
// decision.
//
// IMPORTANT: this is NOT a security boundary. It is a static safety net that
// reads the command text without executing anything and deliberately errs
// toward a higher level. A determined or lucky adversary can always build a
// command the classifier rates too low (aliases, functions defined in earlier
// commands, programs that execute their own arguments, remote state the text
// does not show). Treat the result as advice for a human approval prompt, never
// as a guarantee that a Low command is safe or that a High one is malicious.
//
// The command is tokenized with shell-like rules (quotes, escapes, command
// substitution, subshells, pipelines, lists, here-documents, line
// continuations). Every simple command found, including those inside
// substitutions and `bash -c` scripts, is classified through data tables (see
// tables.go) and the final level is the maximum. Input that cannot be parsed,
// is nested too deeply or is longer than 8 KiB is at least High.
package risk

import (
	"slices"
	"strings"

	"motty/internal/shellkind"
)

// Level is the risk of a command. Levels are ordered: a higher value is riskier.
type Level uint8

const (
	// Low is read-only inspection with no side effects.
	Low Level = iota
	// Medium changes files or configuration with a bounded effect.
	Medium
	// High deletes data, changes permissions or privileges, stops services,
	// executes unseen code, or is otherwise hard to undo.
	High
	// Critical can destroy the machine, its data or the remote access to it.
	Critical
)

// String returns the level name.
func (l Level) String() string {
	switch l {
	case Low:
		return "Low"
	case Medium:
		return "Medium"
	case High:
		return "High"
	case Critical:
		return "Critical"
	}
	return "Unknown"
}

// Assessment is the result of Classify.
type Assessment struct {
	Level          Level
	ApprovalReason string
	// Reasons are short human-readable explanations of the highest level.
	Reasons []string
	// Safer optionally suggests a lower-risk alternative; it may be empty.
	Safer string
}

const (
	maxInput   = 8 << 10 // longer commands are at least High
	maxDepth   = 10      // nesting of substitutions, wrappers and shell -c scripts
	maxReasons = 6
	workBudget = 4000 // parsed scripts and simple commands per Classify call
)

// Classify assesses a shell command line without running it. It never panics
// and its work is bounded by the input size.
func Classify(command string) Assessment {
	st := &state{budget: workBudget}
	var a acc
	src := command
	if len(src) > maxInput {
		a.requireApproval(High, "very long command (over 8 KiB) cannot be reviewed reliably",
			"Split the work into several smaller commands")
		src = src[:maxInput]
	}
	if strings.IndexByte(src, 0) >= 0 {
		a.requireApproval(High, "command contains a NUL byte", "")
	}
	if compact := strings.Join(strings.Fields(src), ""); strings.Contains(compact, "(){") && strings.Contains(compact, "|") &&
		(strings.Contains(compact, ":(){:|:&};:") || strings.Contains(compact, ":(){:|:&}")) {
		a.add(Critical, "fork bomb", "")
	}
	a.merge(st.analyze(src, 0))
	return a.assessment()
}

func ClassifyForShell(command string, kind shellkind.Kind) Assessment {
	return Classify(command).ForShell(kind)
}

// ForShell adjusts a POSIX classification for the target shell.
func (assessment Assessment) ForShell(kind shellkind.Kind) Assessment {
	if kind != shellkind.POSIX && assessment.Level < Critical {
		if assessment.Level < High {
			assessment.Level = High
			if assessment.ApprovalReason == "" {
				assessment.Reasons = nil
			}
		}
		reason := "POSIX risk rules cannot verify commands for " + kind.String()
		assessment.Reasons = append(assessment.Reasons, reason)
		if assessment.ApprovalReason == "" {
			assessment.ApprovalReason = reason
		}
		assessment.Safer = ""
	}
	return assessment
}

// Policy decides what the assistant may do without asking.
type Policy struct {
	// AutoUpTo is the highest level executed without asking. Critical is never
	// automatic: a value of Critical is treated as High.
	AutoUpTo Level
	// Enabled turns automatic execution on. When false every non-critical
	// command needs approval.
	Enabled bool
	// BlockCritical refuses Critical commands outright instead of asking for a
	// typed confirmation.
	BlockCritical bool
}

// Decision is the outcome of Policy.Decide.
type Decision uint8

const (
	// DecisionAuto: run without asking.
	DecisionAuto Decision = iota
	// DecisionAsk: ask the user to approve.
	DecisionAsk
	// DecisionConfirmText: critical; the user must type a confirmation.
	DecisionConfirmText
	// DecisionBlock: refuse (only when Policy.BlockCritical is set).
	DecisionBlock
)

// String returns the decision name.
func (d Decision) String() string {
	switch d {
	case DecisionAuto:
		return "Auto"
	case DecisionAsk:
		return "Ask"
	case DecisionConfirmText:
		return "ConfirmText"
	case DecisionBlock:
		return "Block"
	}
	return "Unknown"
}

// Decide maps an assessment to an action under the policy.
func (p Policy) Decide(a Assessment) Decision {
	if a.Level >= Critical {
		if p.BlockCritical {
			return DecisionBlock
		}
		return DecisionConfirmText
	}
	if !p.Enabled || a.ApprovalReason != "" {
		return DecisionAsk
	}
	limit := p.AutoUpTo
	if limit >= Critical {
		limit = High
	}
	if a.Level <= limit {
		return DecisionAuto
	}
	return DecisionAsk
}

// entry is one reason recorded at the accumulator's current level.
type entry struct {
	why   string
	safer string
}

// acc accumulates findings. It keeps only the reasons of the highest level seen.
type acc struct {
	level          Level
	es             []entry
	approvalReason string
}

func (a *acc) add(l Level, why, safer string) {
	if l == Low || l < a.level {
		return
	}
	if l > a.level {
		a.level = l
		a.es = a.es[:0]
	}
	for _, e := range a.es {
		if e.why == why {
			return
		}
	}
	if len(a.es) < maxReasons {
		a.es = append(a.es, entry{why, safer})
	}
}

func (a *acc) requireApproval(level Level, reason, safer string) {
	a.recordApproval(reason)
	a.add(level, reason, safer)
}

func (a *acc) recordApproval(reason string) {
	if a.approvalReason == "" {
		a.approvalReason = reason
	}
}

func (a *acc) merge(b acc) {
	a.recordApproval(b.approvalReason)
	for _, e := range b.es {
		a.add(b.level, e.why, e.safer)
	}
}

func (a *acc) saferHint() string {
	for _, e := range a.es {
		if e.safer != "" {
			return e.safer
		}
	}
	return ""
}

func (a *acc) assessment() Assessment {
	out := Assessment{Level: a.level, ApprovalReason: a.approvalReason, Safer: a.saferHint()}
	for _, e := range a.es {
		out.Reasons = append(out.Reasons, e.why)
	}
	if a.level == Low {
		out.Reasons = []string{"read-only or no side effects detected"}
	}
	if a.approvalReason != "" && !slices.Contains(out.Reasons, a.approvalReason) {
		out.Reasons = append(out.Reasons, a.approvalReason)
	}
	return out
}
