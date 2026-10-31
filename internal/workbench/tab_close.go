package workbench

import (
	"fmt"

	"github.com/vivaui/viva/components"
	"github.com/vivaui/viva/ui"
	layoutcore "motty/internal/workspace"
)

// tabsClose holds exactly the tabs covered by one close confirmation.
type tabsClose struct {
	keep   layoutcore.WorkspaceID
	ids    []layoutcore.WorkspaceID
	count  int
	locked int
	title  string
}

// askCloseTabs confirms a batch or a protected tab; one unlocked tab closes
// immediately, just like its own close button.
func (state *State) askCloseTabs(keep layoutcore.WorkspaceID, pick func(position int) bool) {
	pending := tabsClose{keep: keep}
	for position, tab := range state.workspaceTabs {
		if pick(position) {
			pending.ids = append(pending.ids, tab.ID)
			pending.count++
			if tab.Locked {
				pending.locked++
				pending.title = state.tabLabel(tab)
			}
		}
	}
	if pending.count < 2 && pending.locked == 0 {
		state.closeTabs(pending)
		return
	}
	state.tabsClose = pending
	state.modal = modalCloseTabs
}

func (state *State) askCloseLockedTab(id layoutcore.WorkspaceID) {
	index, ok := state.workspaceTab(id)
	if !ok {
		return
	}
	state.tabsClose = tabsClose{ids: []layoutcore.WorkspaceID{id}, count: 1, locked: 1, title: state.tabLabel(state.workspaceTabs[index])}
	state.modal = modalCloseTabs
}

func (state *State) clickCloseTabsDialog(id ui.ID) {
	switch id {
	case hitTabsCloseDismiss, hitTabsCloseClose, hitTabsCloseCancel:
		state.modal = modalNone
		state.tabsClose = tabsClose{}
	case hitTabsCloseConfirm:
		pending := state.tabsClose
		state.modal = modalNone
		state.tabsClose = tabsClose{}
		state.closeTabs(pending)
	}
}

// closeTabsKey makes Enter on the confirm button confirm.
func (state *State) closeTabsKey(event ui.KeyEvent) (ui.EventResult, bool) {
	if state.modal != modalCloseTabs || event.Key != ui.KeyEnter || event.Target != hitTabsCloseConfirm || event.Repeat {
		return ui.EventResult{}, false
	}
	state.clickCloseTabsDialog(hitTabsCloseConfirm)
	return ui.EventResult{Handled: true, Repaint: true}, true
}

func (state *State) paintCloseTabsDialog(canvas *ui.Canvas, viewport ui.Rect) {
	messages := state.messages
	dialog := components.BeginDialog(canvas, state.Theme(), viewport, components.DialogOptions{
		Layer: dialogLayer, Scope: dialogScope,
		DismissID: hitTabsCloseDismiss, CloseID: hitTabsCloseClose, InitialFocusID: hitTabsCloseCancel,
		ContentSize: ui.Size{Width: 520}, FitBody: true,
	})
	title := fmt.Sprintf(messages.CloseTabsTitleFmt, state.tabsClose.count)
	description := messages.CloseTabsDescription
	if state.tabsClose.locked > 0 {
		description = fmt.Sprintf(messages.CloseLockedTabsDescriptionFmt, state.tabsClose.locked)
		if state.tabsClose.count == 1 {
			title = messages.CloseLockedTabTitle
			description = fmt.Sprintf(messages.CloseLockedTabDescriptionFmt, state.tabsClose.title)
		}
	}
	layout := dialog.Begin(title, description)
	dialog.Actions(layout,
		components.ButtonAction{ID: hitTabsCloseCancel, Label: messages.Cancel, Variant: components.ButtonSecondary},
		components.ButtonAction{ID: hitTabsCloseConfirm, Label: messages.CloseTabsConfirm, Variant: components.ButtonDestructive},
	)
	dialog.End()
}
