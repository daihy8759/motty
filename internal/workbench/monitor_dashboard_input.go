package workbench

import (
	"strings"

	"github.com/vivaui/viva/components"
	"github.com/vivaui/viva/ui"
	"motty/internal/monitoring"
)

func (s *State) restoreDashboard(panels []monitoring.Panel, active string) {
	// A live local-state refresh must not reconnect or discard running panels.
	if len(s.dashboard.sources) > 0 {
		return
	}
	d := &s.dashboard
	for _, running := range d.running {
		if running {
			return
		}
	}
	previous := d.panels
	d.panels = nil
	d.running = nil
	d.active = ""
	d.rows = nil
	seen := make(map[string]bool)
	for _, p := range panels {
		if p.ID == "" || seen[p.ID] || strings.TrimSpace(p.Name) == "" {
			continue
		}
		p.Normalize()
		seen[p.ID] = true
		d.panels = append(d.panels, p)
		d.engine.Set(p, false)
		if p.ID == active {
			d.active = p.ID
		}
	}
	for _, old := range previous {
		if !seen[old.ID] {
			d.engine.Remove(old.ID)
		}
	}
	if d.active == "" && len(d.panels) > 0 {
		d.active = d.panels[0].ID
	}
}
func (s *State) dashboardArea() components.ScrollArea {
	d := &s.dashboard
	w := d.body.Width
	if p := s.dashboardPanel(); p != nil && p.Simple {
		w = max(w, 960)
	}
	return components.BeginScrollArea(nil, s.Theme(), d.body, ui.Size{Width: w, Height: d.content}).Offset(d.scrollX, d.scroll)
}
func (s *State) dashboardScroll(e ui.ScrollEvent) ui.EventResult {
	d := &s.dashboard
	if s.modal == modalDashboardAdd {
		return ui.EventResult{}
	}
	if s.modal == modalDashboard {
		if d.editor.groupOpen {
			return ui.EventResult{}
		}
		if pointInRect(e.X, e.Y, d.editor.bounds) {
			before := d.editor.scroll
			d.editor.scroll = min(max(0, before+e.DeltaY), max(0, d.editor.content-d.editor.bounds.Height))
			return ui.EventResult{Handled: true, Repaint: before != d.editor.scroll}
		}
		return ui.EventResult{Handled: true}
	}
	if s.modal != modalNone || s.activeSection != sectionDashboard || d.menu != 0 || !pointInRect(e.X, e.Y, d.body) {
		return ui.EventResult{}
	}
	before, x := d.scroll, d.scrollX
	g := s.dashboardArea().Geometry()
	d.scroll = min(max(0, before+e.DeltaY), g.MaxOffsetY)
	d.scrollX = min(max(0, x+e.DeltaX), g.MaxOffsetX)
	return ui.EventResult{Handled: true, Repaint: before != d.scroll || x != d.scrollX}
}
func (s *State) dashboardKey(e ui.KeyEvent) ui.EventResult {
	if s.modal == modalDashboardAdd {
		if e.Key == ui.KeyEscape && !e.Release {
			s.closeModal()
			return ui.EventResult{Handled: true, Repaint: true}
		}
		return ui.EventResult{}
	}
	if e.Release {
		return ui.EventResult{}
	}
	if s.modal == modalDashboard {
		if s.dashboard.editor.groupOpen && e.Key == ui.KeyEscape {
			s.dashboard.editor.groupOpen = false
			return ui.EventResult{Handled: true, Repaint: true, Focus: hitDashboardGroupFilter, FocusVisible: true}
		}
		if e.Target == hitDashboardGroupFilter && e.Key == ui.KeyDown {
			s.dashboard.editor.groupOpen = true
			return ui.EventResult{Handled: true, Repaint: true, Focus: hitDashboardGroupList.At(0), FocusVisible: true}
		}
		if s.dashboard.editor.page == 1 {
			move, result := s.dashboard.editor.order.Key(e)
			if result.Handled {
				s.moveDashboardHost(move)
				return result
			}
		}
		if e.Target == hitDashboardPickTab || e.Target == hitDashboardOrderTab {
			options := s.dashboardEditorTabs()
			if next, ok := components.TabsKeyDown(e.Target, options[:], components.TabsHorizontal, components.DirectionLTR, e.Key); ok {
				return ui.EventResult{Handled: true, Repaint: true, Focus: next, FocusVisible: true}
			}
		}
		if e.Target == hitDashboardHostScroll {
			editor := &s.dashboard.editor
			area := components.BeginScrollArea(nil, s.Theme(), editor.bounds, ui.Size{Width: editor.bounds.Width, Height: editor.content})
			if _, y, ok := area.ScrollForKey(0, editor.scroll, e.Key, 32); ok {
				editor.scroll = y
				return ui.EventResult{Handled: true, Repaint: true}
			}
		}
		if e.Key == ui.KeyEscape {
			s.closeModal()
			s.showNextPrompt()
			return ui.EventResult{Handled: true, Repaint: true}
		}
		if e.Key == ui.KeyEnter && !e.Repeat && (e.Target == hitDashboardName || e.Target == hitDashboardNote) {
			s.submitDashboard()
			return ui.EventResult{Handled: true, Repaint: true}
		}
		return ui.EventResult{}
	}
	if s.modal != modalNone || s.activeSection != sectionDashboard {
		return ui.EventResult{}
	}
	if e.Target == hitDashboardSimple || e.Target == hitDashboardDetailed {
		options := s.dashboardModeTabs()
		if next, ok := components.TabsKeyDown(e.Target, options[:], components.TabsHorizontal, components.DirectionLTR, e.Key); ok {
			return ui.EventResult{Handled: true, Repaint: true, Focus: next, FocusVisible: true}
		}
	}
	if e.Target.Scope() == hitDashboardViewList || e.Target.Scope() == hitDashboardSimpleViewList {
		simple := e.Target.Scope() == hitDashboardSimpleViewList
		host := uint32(item(e.Target) / 3)
		options := s.dashboardViewOptions(host, simple)
		orientation := components.TabsHorizontal
		if simple {
			orientation = components.TabsVertical
		}
		if next, ok := components.TabsKeyDown(e.Target, options[:], orientation, components.DirectionLTR, e.Key); ok {
			return ui.EventResult{Handled: true, Repaint: true, Focus: next, FocusVisible: true}
		}
	}
	if s.dashboard.menu != 0 {
		if next, ok := s.selectScroll(true, hitDashboardDismiss).Navigate(e.Key, e.Target, true); ok {
			return ui.EventResult{Handled: true, Repaint: true, Focus: next, FocusVisible: true}
		}
	}
	if e.Key == ui.KeyDown {
		menu := 0
		first := ui.ID{}
		switch e.Target {
		case hitDashboardSwitch:
			menu = 1
			first = hitDashboardPanelList.At(0)
		case hitDashboardInterval:
			menu = 2
			first = hitDashboardIntervalList.At(0)
		case hitDashboardRetention:
			menu = 3
			first = hitDashboardRetentionList.At(0)
		}
		if menu != 0 {
			s.dashboard.menu = menu
			return ui.EventResult{Handled: true, Repaint: true, Focus: first, FocusVisible: true}
		}
	}
	if e.Key == ui.KeyEscape && s.dashboard.menu != 0 {
		s.dashboard.menu = 0
		return ui.EventResult{Handled: true, Repaint: true}
	}
	if e.Target == hitDashboardScroll {
		g := s.dashboardArea()
		if x, y, handled := g.ScrollForKey(s.dashboard.scrollX, s.dashboard.scroll, e.Key, 32); handled {
			s.dashboard.scrollX = x
			s.dashboard.scroll = y
			return ui.EventResult{Handled: true, Repaint: true}
		}
	}
	// Page keys scroll the page from any of its controls, so following a long
	// panel does not first require Tab-ing to the scroll viewport. A text field
	// keeps its own page keys.
	if (e.Key == ui.KeyPageUp || e.Key == ui.KeyPageDown) && s.EditorFor(e.Target) == nil {
		g := s.dashboardArea()
		if x, y, handled := g.ScrollForKey(s.dashboard.scrollX, s.dashboard.scroll, e.Key, 32); handled {
			s.dashboard.scrollX = x
			s.dashboard.scroll = y
			return ui.EventResult{Handled: true, Repaint: true}
		}
	}
	return ui.EventResult{}
}
func (s *State) dashboardPointer(e ui.PointerEvent) (ui.EventResult, bool) {
	d := &s.dashboard
	if s.modal == modalDashboard {
		editor := &d.editor
		if editor.page == 1 {
			move, result := editor.order.Pointer(e)
			if result.Handled {
				s.moveDashboardHost(move)
				return result, true
			}
		}
		area := components.BeginScrollArea(nil, s.Theme(), editor.bounds, ui.Size{Width: editor.bounds.Width, Height: editor.content}).Offset(0, editor.scroll)
		if e.Kind == ui.PointerDown && e.Target == hitDashboardHostThumb {
			d.dragging = true
			d.grab = e.Y - area.Geometry().VerticalThumb.Y
			return ui.EventResult{Handled: true, Focus: hitDashboardHostScroll}, true
		}
		if d.dragging {
			if e.Kind == ui.PointerMove || e.Kind == ui.PointerUp {
				editor.scroll = area.Geometry().VerticalOffsetForThumb(e.Y - d.grab)
				if e.Kind == ui.PointerUp {
					d.dragging = false
				}
				return ui.EventResult{Handled: true, Repaint: true}, true
			}
			if e.Kind == ui.PointerExit {
				d.dragging = false
			}
			return ui.EventResult{Handled: true}, true
		}
		return ui.EventResult{}, false
	}
	if s.modal != modalNone || s.activeSection != sectionDashboard {
		return ui.EventResult{}, false
	}
	if e.Kind == ui.PointerDown && (e.Target == hitDashboardThumb || e.Target == hitDashboardXThumb) && e.Button == ui.PointerButtonPrimary {
		d.dragging = true
		d.dragX = e.Target == hitDashboardXThumb
		g := s.dashboardArea().Geometry()
		d.grab = e.Y - g.VerticalThumb.Y
		if d.dragX {
			d.grab = e.X - g.HorizontalThumb.X
		}
		return ui.EventResult{Handled: true, Focus: hitDashboardScroll}, true
	}
	if !d.dragging {
		return ui.EventResult{}, false
	}
	if e.Kind == ui.PointerMove || e.Kind == ui.PointerUp {
		g := s.dashboardArea().Geometry()
		if d.dragX {
			d.scrollX = min(max(0, (e.X-d.grab-g.HorizontalTrack.X)/max(1, g.HorizontalTrack.Width-g.HorizontalThumb.Width)*g.MaxOffsetX), g.MaxOffsetX)
		} else {
			d.scroll = g.VerticalOffsetForThumb(e.Y - d.grab)
		}
		if e.Kind == ui.PointerUp {
			d.dragging = false
		}
		return ui.EventResult{Handled: true, Repaint: true}, true
	}
	if e.Kind == ui.PointerExit {
		d.dragging = false
	}
	return ui.EventResult{Handled: true}, true
}
