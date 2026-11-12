package workbench

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/vivaui/viva/app"
	"github.com/vivaui/viva/gfx"
	"motty/internal/ai/risk"
	"motty/internal/i18n"
)

func TestApprovalButtonBackgroundStaysAboveTheCard(t *testing.T) {
	for _, look := range []appearance{appearanceLight, appearanceDark} {
		for _, size := range []gfx.Size{panelWide, panelNarrow} {
			for _, scenario := range []struct {
				name       string
				level      risk.Level
				needsText  bool
				escalation bool
			}{
				{name: "medium", level: risk.Medium},
				{name: "high", level: risk.High},
				{name: "critical", level: risk.Critical, needsText: true},
				{name: "escalation", level: risk.Medium, escalation: true},
			} {
				t.Run(fmt.Sprintf("%s/%g/%s", look, size.Width, scenario.name), func(t *testing.T) {
					state, _ := panelState(t, nil)
					withModel(t, state)
					state.setLanguage(i18n.Chinese)
					state.setAppearance(look)
					approval := approvalFixture(state, scenario.level, scenario.needsText)
					approval.escalation = scenario.escalation
					view := openAIPanelView(t, state)
					defer view.Close()
					if err := view.Resize(int(size.Width), int(size.Height)); err != nil {
						t.Fatal(err)
					}
					if err := view.Rest(); err != nil {
						t.Fatal(err)
					}
					snapshot := view.Snapshot()
					var approve gfx.Hit
					for _, hit := range snapshot.Hits {
						if hit.ID == hitAIApprove {
							approve = hit
							break
						}
					}
					if approve.Bounds.Width == 0 || approve.Disabled != scenario.needsText {
						t.Fatalf("approval button missing or incorrectly enabled: %+v", approve)
					}
					sampleX, sampleY := approve.Bounds.X+12, approve.Bounds.Y+approve.Bounds.Height/2
					var top app.Primitive
					for _, primitive := range snapshot.Primitives {
						if primitive.Kind != app.RectanglePrimitive || primitive.Color.Alpha == 0 ||
							!pointInRect(sampleX, sampleY, primitive.Bounds) ||
							primitive.Clipped && !pointInRect(sampleX, sampleY, primitive.Clip) {
							continue
						}
						if primitive.Layer >= top.Layer {
							top = primitive
						}
					}
					if top.Bounds != approve.Bounds {
						t.Fatalf("approval button background is covered: top=%+v button=%+v", top, approve.Bounds)
					}
					if !scenario.needsText {
						want := state.pal.accent
						if !scenario.escalation && scenario.level >= risk.High {
							want = state.pal.danger
						}
						if top.Color != want {
							t.Fatalf("approval background = %+v, want %+v", top.Color, want)
						}
					}
					if dir := os.Getenv("MOTTY_APPROVAL_SCREENSHOTS"); dir != "" && scenario.name == "medium" {
						if err := os.MkdirAll(dir, 0700); err != nil {
							t.Fatal(err)
						}
						if err := view.Screenshot(filepath.Join(dir, fmt.Sprintf("approval-%s-%g.png", look, size.Width))); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		}
	}
}
