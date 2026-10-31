package workbench

import (
	"github.com/vivaui/viva/components"
	"github.com/vivaui/viva/ui"
)

// localShellPickerHits is the place of the controls this file paints.
var localShellPickerHits = tree.Feature("local-shell-picker")

var (
	hitLocalShellPickerDismiss = tree.ID(localShellPickerHits, "local-shell-picker-dismiss")
	hitLocalShellPickerItems   = tree.Sub(localShellPickerHits, tree.Name("local-shell-picker-item"))
)

// localShellPicker is the menu that opens a local terminal with one chosen
// shell, instead of the default one of the settings. Closed, it costs nothing.
type localShellPicker struct {
	open bool
	at   ui.Point
	// inPane is set when it was opened from the new-tab page: the shell then
	// starts in that empty pane, like the page's own Local Terminal row.
	inPane bool
}

// openLocalShellPicker opens the menu at at, and reports whether this computer
// offers a choice of shells at all. The shells are looked up again each time,
// since one may have been installed since; the WSL distributions follow when
// wsl.exe has named them.
func (state *State) openLocalShellPicker(at ui.Point, inPane bool) bool {
	if !localShellSettingVisible() || state.modal != modalNone {
		return false
	}
	state.refreshLocalShells()
	state.localShellPicker = localShellPicker{open: true, at: at, inPane: inPane}
	return true
}

// openLocalShellPickerOn is called while painting a Local Terminal entry: when
// this paint is the event pass of a secondary press on it, the menu opens there.
func (state *State) openLocalShellPickerOn(canvas *ui.Canvas, id ui.ID, inPane bool) {
	event, ok := canvas.PointerOn(id)
	if !ok || event.Kind != ui.PointerDown || event.Button != ui.PointerButtonSecondary {
		return
	}
	if state.openLocalShellPicker(ui.Point{X: event.X, Y: event.Y}, inPane) {
		canvas.Consume()
	}
}

// localShellPickerPointer closes an open menu on a secondary press outside it.
func (state *State) localShellPickerPointer(event ui.PointerEvent) (ui.EventResult, bool) {
	if event.Kind != ui.PointerDown || event.Button == ui.PointerButtonNone || event.Button == ui.PointerButtonPrimary {
		return ui.EventResult{}, false
	}
	if state.localShellPicker.open && event.Target == hitLocalShellPickerDismiss {
		state.localShellPicker.open = false
		return ui.EventResult{Handled: true, Repaint: true}, true
	}
	return ui.EventResult{}, false
}

func (state *State) paintLocalShellPicker(canvas *ui.Canvas, viewport ui.Rect) {
	picker := &state.localShellPicker
	if !picker.open {
		return
	}
	if state.modal != modalNone || !localShellSettingVisible() {
		picker.open = false
		return
	}
	state.adoptWSLDistros()
	m, menuState := state.messages, &state.localShellMenu
	selected := state.localShellSelected()
	icon := lucideIcons[iconTerminal]
	var rows menuRows
	for index, choice := range menuState.choices {
		item := components.ContextMenuItem{ID: hitLocalShellPickerItems.At(index), Label: choice.Name, Icon: icon}
		if index == selected {
			item.Shortcut = m.LocalShellDefault
		}
		rows.add(item)
	}
	if len(menuState.choices) == 0 {
		rows.add(components.ContextMenuItem{ID: hitLocalShellPickerItems.At(0), Label: m.SettingsLocalShellEmpty, Icon: icon, Disabled: true})
	}
	width, height := rows.size(canvas, state.contextMenuTheme())
	bounds := state.popupAt(canvas, viewport, picker.at, width, height, 6)
	menu := components.BeginContextMenu(canvas, state.contextMenuTheme(), bounds, components.ContextMenuOptions{
		Layer: dialogLayer, Scope: dialogScope, DismissID: hitLocalShellPickerDismiss, Viewport: viewport, Scroll: state.menuScrollFor(hitLocalShellPickerDismiss),
		RowHeight: contextMenuRow,
	})
	state.menuPlaced(menu.Bounds())
	rows.paint(&menu, nil)
	menu.End()
}

// clickLocalShellPicker runs a menu choice. A press anywhere else only closes it.
func (state *State) clickLocalShellPicker(id ui.ID) bool {
	picker := state.localShellPicker
	if !picker.open {
		return false
	}
	state.localShellPicker.open = false
	index, ok := id.In(hitLocalShellPickerItems)
	choices := state.localShellMenu.choices
	if !ok || index < 0 || index >= len(choices) {
		return true
	}
	if picker.inPane {
		state.pendingWorkspace = state.deck.ActiveWorkspace()
		state.pendingPane = state.deck.ActivePane(state.pendingWorkspace)
	} else {
		state.pendingWorkspace, state.pendingPane = 0, 0
	}
	state.openLocalTerminalWith(choices[index])
	return true
}
