package workbench

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/vivaui/viva/components"
	"github.com/vivaui/viva/flex"
	"github.com/vivaui/viva/text"
	"github.com/vivaui/viva/ui"
	"motty/internal/loginexpect"
)

// loginExpectStepState is one rule being edited in its own dialog. index is -1
// when the dialog adds a rule rather than changing one.
type loginExpectStepState struct {
	active      bool
	index       int
	expect      text.Editor
	send        text.Editor
	timeout     text.Editor
	delay       text.Editor
	appendEnter bool
	sensitive   bool
	commandMode bool
	err         string
}

// loginExpectSectionHeight is the room the section takes in the host form: its
// header alone while closed, and the hint, the enable box, one row per rule and
// the add button while open.
func (state *State) loginExpectSectionHeight() float32 {
	height := float32(advancedHeaderHeight)
	editor := &state.editor
	if !editor.loginExpectOpen {
		return height
	}
	height += 34 // the hint, two short lines
	height += 30 // the enable checkbox
	height += float32(len(editor.loginExpect.Steps)) * 34
	height += 40 // the add button
	height += 6
	return height
}

// paintLoginExpectSection draws the collapsible Expect/Send list in the host
// dialog. The rules themselves are edited in a dialog of their own; this shows
// their order and lets them be moved or removed.
func (state *State) paintLoginExpectSection(canvas *ui.Canvas, bounds ui.Rect) {
	m, pal := state.messages.LoginExpect, state.pal
	editor := &state.editor
	open := editor.loginExpectOpen
	header := ui.Rect{X: bounds.X, Y: bounds.Y + advancedHeaderGap, Width: bounds.Width, Height: 32}
	state.rememberHostControl(hitDialogLoginExpectHeader, header)
	chevron := iconChevronRight
	if open {
		chevron = iconChevronDown
	}
	var icon flex.Box
	f := state.partLayout.Begin(canvas, state.Theme(), header)
	f.Row().Fill().PadSides(0, 0, 0, 2).Gap(8).Items(flex.Center).
		Radius(radius.control).HoverBackground(pal.surfaceSoft).
		HitWith(hitDialogLoginExpectHeader, m.SectionTitle, ui.HitOptions{Role: ui.RoleButton, Expanded: open}).
		Children(func() {
			icon = f.Slot().Size(16, 16)
			f.Text(m.SectionTitle).FontSize(metrics.FontSizeM).Weight(ui.WeightMedium).Color(pal.muted).LineHeight(20)
			if count := len(editor.loginExpect.Steps); count > 0 {
				f.Text(fmt.Sprintf("%d", count)).FontSize(metrics.FontSizeS).Color(pal.muted).LineHeight(20)
			}
		})
	f.End()
	paintIcon(canvas, uint8(chevron), icon.Rect(), pal.muted)
	if !open {
		return
	}

	body := ui.Rect{
		X: bounds.X, Y: bounds.Y + advancedHeaderHeight,
		Width: bounds.Width, Height: max(bounds.Height-advancedHeaderHeight, 0),
	}
	var enable flex.Box
	f = state.partLayout.Begin(canvas, state.Theme(), body)
	f.Column().Fill().Children(func() {
		f.Paragraph(m.SectionHint, 2).FontSize(metrics.FontSizeS).Color(pal.muted).LineHeight(15)
		enable = state.declareDialogCheckbox(f, m.Enabled, 6, 0)
		for index := range editor.loginExpect.Steps {
			state.declareLoginExpectRow(f, index)
		}
		f.Row().Height(34).Gap(8).Children(func() {
			f.Button(hitDialogLoginExpectAdd, m.Add).Outline()
		})
	})
	f.End()
	state.paintDialogCheckbox(canvas, hitDialogLoginExpectEnable, m.Enabled, editor.loginExpect.Enabled, enable)
}

// declareLoginExpectRow lays out one saved rule: its summary, then the buttons
// that move, edit and remove it. The buttons belong to the form's scroll tree.
func (state *State) declareLoginExpectRow(f *flex.Frame, index int) {
	m, pal := state.messages.LoginExpect, state.pal
	row := f.Row().Height(34).Gap(6).Items(flex.Center).Children(func() {
		f.Text(state.loginExpectStepSummary(index)).FontSize(metrics.FontSizeS).Color(pal.text).Grow(1).LineHeight(18)
		f.Button(hitDialogLoginExpectUpList.At(index), m.MoveUp).Small().Ghost().Disabled(index == 0)
		f.Button(hitDialogLoginExpectDownList.At(index), m.MoveDown).Small().Ghost().Disabled(index == len(state.editor.loginExpect.Steps)-1)
		f.Button(hitDialogLoginExpectEditList.At(index), m.Edit).Small().Outline()
		f.Button(hitDialogLoginExpectDeleteList.At(index), m.Delete).Small().Ghost()
	})
	state.rememberHostControl(hitDialogLoginExpectEditList.At(index), row.Rect())
}

func (state *State) loginExpectStepSummary(index int) string {
	steps := state.editor.loginExpect.Steps
	if index < 0 || index >= len(steps) {
		return ""
	}
	step, m := steps[index], state.messages.LoginExpect
	wait := step.Expect
	if wait == "" {
		wait = "—"
	}
	reply := step.Send
	if step.Sensitive {
		reply = m.AskedSummary
	} else if reply == "" {
		reply = "—"
	} else if step.AppendEnter {
		reply += m.EnterSummary
	}
	seconds := int(step.Timeout / time.Second)
	summary := fmt.Sprintf(m.StepSummaryFmt, clipLoginExpectText(wait), clipLoginExpectText(reply), seconds)
	if milliseconds := loginexpect.DelayMilliseconds(step.Delay); milliseconds > 0 {
		summary += fmt.Sprintf(m.DelaySummaryFmt, milliseconds)
	}
	return fmt.Sprintf("%d. %s", index+1, summary)
}

func clipLoginExpectText(value string) string {
	const limit = 28
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit-1]) + "…"
}

// clickLoginExpect handles the section's own controls in the host dialog.
func (state *State) clickLoginExpect(id ui.ID) bool {
	switch id {
	case hitDialogLoginExpectHeader:
		state.editor.loginExpectOpen = !state.editor.loginExpectOpen
		return true
	case hitDialogLoginExpectEnable:
		state.editor.loginExpect.Enabled = !state.editor.loginExpect.Enabled
		if state.editor.loginExpect.Enabled {
			state.editor.loginExpectOpen = true
		}
		return true
	case hitDialogLoginExpectAdd:
		state.openLoginExpectStep(-1)
		return true
	}
	if index, ok := id.In(hitDialogLoginExpectEditList); ok {
		state.openLoginExpectStep(index)
		return true
	}
	if index, ok := id.In(hitDialogLoginExpectUpList); ok {
		state.moveLoginExpectStep(index, -1)
		return true
	}
	if index, ok := id.In(hitDialogLoginExpectDownList); ok {
		state.moveLoginExpectStep(index, 1)
		return true
	}
	if index, ok := id.In(hitDialogLoginExpectDeleteList); ok {
		state.removeLoginExpectStep(index)
		return true
	}
	return false
}

func (state *State) moveLoginExpectStep(index, direction int) {
	steps := &state.editor.loginExpect.Steps
	target := index + direction
	if index < 0 || index >= len(*steps) || target < 0 || target >= len(*steps) {
		return
	}
	(*steps)[index], (*steps)[target] = (*steps)[target], (*steps)[index]
}

func (state *State) removeLoginExpectStep(index int) {
	steps := &state.editor.loginExpect.Steps
	if index < 0 || index >= len(*steps) {
		return
	}
	*steps = append((*steps)[:index], (*steps)[index+1:]...)
}

// openLoginExpectStep opens the rule editor: index -1 adds a rule.
func (state *State) openLoginExpectStep(index int) {
	step := loginexpect.Step{Timeout: loginexpect.DefaultTimeoutSeconds * time.Second, AppendEnter: true}
	if index >= 0 && index < len(state.editor.loginExpect.Steps) {
		step = state.editor.loginExpect.Steps[index]
	} else {
		index = -1
	}
	editor := &state.loginExpectStep
	editor.active, editor.index = true, index
	editor.expect = text.Editor{}
	editor.expect.Insert(step.Expect)
	editor.send = text.Editor{}
	if !step.Sensitive {
		editor.send.Insert(step.Send)
	}
	seconds := int(step.Timeout / time.Second)
	if seconds <= 0 {
		seconds = loginexpect.DefaultTimeoutSeconds
	}
	editor.timeout = text.Editor{}
	editor.timeout.Insert(strconv.Itoa(seconds))
	editor.delay = text.Editor{}
	milliseconds := loginexpect.DelayMilliseconds(step.Delay)
	editor.delay.Insert(strconv.Itoa(milliseconds))
	editor.appendEnter, editor.sensitive, editor.err = step.AppendEnter, step.Sensitive, ""
	editor.commandMode = step.CommandMode
	state.modal = modalLoginExpectStep
}

// saveLoginExpectStep validates the rule editor and writes it back to the draft.
func (state *State) saveLoginExpectStep() {
	editor := &state.loginExpectStep
	m := state.messages.LoginExpect
	seconds, err := strconv.Atoi(strings.TrimSpace(editor.timeout.String()))
	if err != nil || seconds < 1 {
		editor.err = m.ErrTimeout
		return
	}
	if seconds > loginexpect.MaxTimeoutSeconds {
		seconds = loginexpect.MaxTimeoutSeconds
	}
	delayText := strings.TrimSpace(editor.delay.String())
	if delayText == "" {
		delayText = "0"
	}
	milliseconds, err := strconv.Atoi(delayText)
	if err != nil || milliseconds < 0 {
		editor.err = m.ErrDelay
		return
	}
	if milliseconds > loginexpect.MaxDelayMilliseconds {
		milliseconds = loginexpect.MaxDelayMilliseconds
	}
	step := loginexpect.Step{
		Expect:      editor.expect.String(),
		Send:        editor.send.String(),
		Timeout:     time.Duration(seconds) * time.Second,
		Delay:       loginexpect.DelayFromMilliseconds(milliseconds),
		AppendEnter: editor.appendEnter,
		Sensitive:   editor.sensitive,
		CommandMode: editor.commandMode,
	}
	if step.Sensitive {
		step.Send = ""
	}
	if step.Expect == "" && step.Send == "" && !step.Sensitive {
		editor.err = m.ErrEmpty
		return
	}
	steps := &state.editor.loginExpect.Steps
	if editor.index >= 0 && editor.index < len(*steps) {
		step.ID = (*steps)[editor.index].ID
		(*steps)[editor.index] = step
	} else {
		*steps = append(*steps, step)
	}
	state.editor.loginExpectOpen = true
	state.closeLoginExpectStepEditor()
}

func (state *State) cancelLoginExpectStep() { state.closeLoginExpectStepEditor() }

func (state *State) closeLoginExpectStepEditor() {
	state.loginExpectStep = loginExpectStepState{}
	state.modal = modalNewHost
	state.editor.loginExpectOpen = true
}

// clickLoginExpectStep handles the rule editor's controls.
func (state *State) clickLoginExpectStep(id ui.ID) {
	editor := &state.loginExpectStep
	switch id {
	case hitLoginExpectStepEnter:
		editor.appendEnter = !editor.appendEnter
	case hitLoginExpectStepSensitive:
		editor.sensitive = !editor.sensitive
		if editor.sensitive {
			editor.send = text.Editor{}
		}
	case hitLoginExpectStepCommandMode:
		editor.commandMode = !editor.commandMode
	case hitLoginExpectStepSubmit:
		state.saveLoginExpectStep()
	case hitLoginExpectStepCancel, hitLoginExpectStepClose, hitLoginExpectStepDismiss:
		state.cancelLoginExpectStep()
	}
}

// paintLoginExpectStepDialog draws the editor for one rule.
func (state *State) paintLoginExpectStepDialog(canvas *ui.Canvas, viewport ui.Rect) {
	m, theme := state.messages.LoginExpect, state.Theme()
	editor := &state.loginExpectStep
	title := m.StepTitleAdd
	if editor.index >= 0 {
		title = m.StepTitleEdit
	}
	dialog := components.BeginDialog(canvas, theme, viewport, components.DialogOptions{
		Layer: dialogLayer, Scope: dialogScope,
		DismissID: hitLoginExpectStepDismiss, CloseID: hitLoginExpectStepClose, InitialFocusID: hitLoginExpectStepExpect,
		ContentSize: ui.Size{Width: 520}, FitBody: true, BodyHeight: withError(356, editor.err),
	})
	layout := dialog.Begin(title, "")
	var wait, send, timeout, delay, enterRow, modeRow, sensRow flex.Box
	f := state.settingsRow.Begin(canvas, theme, layout.Body)
	f.Column().Fill().PadSides(2, 4, 0, 4).Children(func() {
		wait = f.Slot().Height(62).MarginSides(0, 0, 4, 0)
		send = f.Slot().Height(62).MarginSides(0, 0, 4, 0)
		timeout = f.Slot().Height(62).MarginSides(0, 0, 4, 0)
		delay = f.Slot().Height(62).MarginSides(0, 0, 4, 0)
		enterRow = state.declareDialogCheckbox(f, m.AppendEnter, 2, 0)
		modeRow = state.declareDialogCheckbox(f, m.CommandMode, 6, 0)
		sensRow = state.declareDialogCheckbox(f, m.Sensitive, 6, 0)
		state.problemLine(f, editor.err)
	})
	f.End()
	state.paintLoginExpectStepField(canvas, hitLoginExpectStepExpect, m.WaitLabel, m.WaitPlaceholder, &editor.expect, wait.Rect(), false, false)
	placeholder := m.SendPlaceholder
	if editor.sensitive {
		placeholder = m.SensitivePlaceholder
	}
	state.paintLoginExpectStepField(canvas, hitLoginExpectStepSend, m.SendLabel, placeholder, &editor.send, send.Rect(), false, editor.sensitive)
	state.paintLoginExpectStepField(canvas, hitLoginExpectStepTimeout, m.TimeoutLabel, "30", &editor.timeout, timeout.Rect(), false, false)
	state.paintLoginExpectStepField(canvas, hitLoginExpectStepDelay, m.DelayLabel, m.DelayPlaceholder, &editor.delay, delay.Rect(), false, false)
	state.paintDialogCheckbox(canvas, hitLoginExpectStepEnter, m.AppendEnter, editor.appendEnter, enterRow)
	state.paintDialogCheckbox(canvas, hitLoginExpectStepCommandMode, m.CommandMode, editor.commandMode, modeRow)
	state.paintDialogCheckbox(canvas, hitLoginExpectStepSensitive, m.Sensitive, editor.sensitive, sensRow)
	dialog.Actions(layout,
		components.ButtonAction{ID: hitLoginExpectStepCancel, Label: state.messages.Cancel, Variant: components.ButtonSecondary},
		components.ButtonAction{ID: hitLoginExpectStepSubmit, Label: m.Save},
	)
	dialog.End()
}

func (state *State) paintLoginExpectStepField(canvas *ui.Canvas, id ui.ID, label, placeholder string, editor *text.Editor, bounds ui.Rect, secure, disabled bool) {
	theme := state.Theme()
	content := components.BeginField(canvas, theme, bounds).Paint(label, "", "")
	value := editor.String()
	focused := canvas.Focused() == id
	components.PaintInput(canvas, theme, content, components.InputSnapshot{
		ID: id, Label: label, Value: value, Placeholder: placeholder, Secure: secure,
		Focused: focused, PlatformEditing: focused && !disabled && value != "", Disabled: disabled,
	})
}

// paintLoginExpectSecretDialog asks for a sensitive rule's response. The answer
// is masked, used once, and never written to the state file or the log.
func (state *State) paintLoginExpectSecretDialog(canvas *ui.Canvas, viewport ui.Rect) {
	m, theme := state.messages.LoginExpect, state.Theme()
	session := state.loginExpectAskSession()
	if session == nil || session.loginExpectAsk == nil {
		return
	}
	ask := session.loginExpectAsk
	dialog := components.BeginDialog(canvas, theme, viewport, components.DialogOptions{
		Layer: dialogLayer, Scope: dialogScope,
		DismissID: hitLoginExpectDismiss, CloseID: hitLoginExpectClose, InitialFocusID: hitLoginExpectField,
		ContentSize: ui.Size{Width: 500}, FitBody: true, BodyHeight: 84,
	})
	layout := dialog.Begin(m.DialogTitle, ask.prompt)
	field := components.BeginField(canvas, theme, state.layoutSecretField(canvas, layout.Body, ""))
	content := field.Paint(m.SendLabel, m.DialogHint, "")
	value := ask.editor.String()
	focused := canvas.Focused() == hitLoginExpectField
	components.PaintInput(canvas, theme, content, components.InputSnapshot{
		ID: hitLoginExpectField, Label: m.SendLabel, Value: value, Placeholder: m.SensitivePlaceholder,
		Secure: true, Focused: focused, PlatformEditing: focused && value != "",
	})
	dialog.Actions(layout,
		components.ButtonAction{ID: hitLoginExpectCancel, Label: state.messages.Cancel, Variant: components.ButtonSecondary},
		components.ButtonAction{ID: hitLoginExpectSubmit, Label: state.messages.Connect},
	)
	dialog.End()
}
