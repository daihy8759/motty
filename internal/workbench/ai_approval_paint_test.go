package workbench

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/vivaui/viva/app"
	"github.com/vivaui/viva/components"
	"github.com/vivaui/viva/gfx"
	"motty/internal/ai/agent"
	"motty/internal/ai/gate"
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

// The pinned question is a card, and the card's own background is one of the
// page's children. The confirming buttons are slots painted by hand, so they
// must be painted after those children; a review found the Allow button reduced
// to its label, near-black on the dark card, because the card's fill covered
// every button surface. This asserts the invariant that matters: whatever is
// painted last over the middle of the button is the button's own surface, not
// something behind it.
func TestTheApprovalButtonsSurfaceIsPaintedOverTheCard(t *testing.T) {
	state, _ := panelState(t, nil)
	withModel(t, state)
	state.ai.mode = agent.ModeAgent
	state.setAIPanelOpen(true)
	state.ai.approvals = append(state.ai.approvals, &aiApproval{request: gate.Request{
		Tool:         "terminal_exec",
		Summary:      "touch created-by-assistant",
		SessionLabel: "staging-web",
		Assessment:   risk.Assessment{Level: risk.Medium},
	}})

	canvas, _ := paintAt(state, panelWide)
	approve := panelHit(t, canvas, hitAIApprove)
	want := components.ButtonRecipe(state.Theme(), components.ButtonDefault, gfx.State{}).Background
	center := gfx.Point{
		X: approve.Bounds.X + approve.Bounds.Width/2,
		Y: approve.Bounds.Y + approve.Bounds.Height/2,
	}

	var last gfx.Rectangle
	found := false
	for _, rectangle := range canvas.Rectangles() {
		bounds := rectangle.Bounds
		if center.X < bounds.X || center.Y < bounds.Y ||
			center.X >= bounds.X+bounds.Width || center.Y >= bounds.Y+bounds.Height {
			continue
		}
		// A translucent tint lets the layers under it show; only an opaque fill
		// can hide the button's surface.
		if rectangle.Color.Alpha < 1 {
			continue
		}
		last, found = rectangle, true
	}
	if !found || last.Bounds != approve.Bounds || last.Color != want {
		t.Fatalf("what is painted last over the approval button's middle is %+v, want the button's own fill %+v at %+v",
			last, want, approve.Bounds)
	}
}
