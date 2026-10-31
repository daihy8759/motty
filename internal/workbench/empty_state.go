package workbench

import (
	"github.com/vivaui/viva/flex"
	"github.com/vivaui/viva/ui"
)

const (
	emptyStateTileSize    = float32(62)
	emptyStateTileRadius  = float32(15)
	emptyStateIconSize    = float32(24)
	emptyStateTitleSize   = float32(17)
	emptyStateActionWidth = float32(160)
)

// declareEmptyPage reserves the shared empty-state layout used by the
// application's catalog pages. The icon sits a little above the middle of the
// available page, followed by one title, one description and, when add is not
// empty, one primary action.
func (state *State) declareEmptyPage(f *flex.Frame, bounds ui.Rect, title, sub, add string) (icon, button flex.Box) {
	return state.declareEmptyPageWithColor(f, bounds, title, sub, add, state.pal.muted)
}

func (state *State) declareEmptyPageWithColor(f *flex.Frame, bounds ui.Rect, title, sub, add string, descriptionColor ui.Color) (icon, button flex.Box) {
	pal := state.pal
	body := max(0, bounds.Height-142)
	contentWidth := min(max(bounds.Width-44, 0), 560)
	f.Column().Grow(1).MarginSides(0, 0, 9, 0).PadSides(max(20, body*0.40-48), 0, 0, 0).Items(flex.Center).Children(func() {
		f.Column().Size(emptyStateTileSize, emptyStateTileSize).Center().Radius(emptyStateTileRadius).Background(pal.surface).Children(func() {
			icon = f.Slot().Size(emptyStateIconSize, emptyStateIconSize)
		})
		f.Text(title).FontSize(emptyStateTitleSize).Weight(ui.WeightSemibold).Color(pal.text).Width(contentWidth).TextCenter().Ellipsis().MarginSides(20, 0, 0, 0)
		f.Paragraph(sub, 4).FontSize(metrics.FontSizeM).Color(descriptionColor).LineHeight(23).Width(contentWidth).TextCenter().MarginSides(8, 0, 0, 0)
		if add != "" {
			button = f.Slot().Size(emptyStateActionWidth, toolbarHeight).MarginSides(20, 0, 0, 0)
		}
	})
	return icon, button
}

// paintEmptyPage paints the boxes declared by declareEmptyPage. An empty label
// leaves the page without an action, which is useful for data that is populated
// by another workflow rather than created on the page.
func (state *State) paintEmptyPage(canvas *ui.Canvas, iconBox, buttonBox flex.Box, icon uint8, id ui.ID, label string, enabled bool) {
	paintIcon(canvas, icon, iconBox.Rect(), state.pal.muted)
	if label == "" {
		return
	}
	button := buttonBox.Rect()
	if button.Width == 0 {
		return
	}
	state.paintToolbarButton(canvas, id, button.X, button.Y, button.Width, label, iconPlus, true, enabled, false)
}
