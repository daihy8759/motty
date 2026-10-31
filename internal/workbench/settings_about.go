package workbench

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"github.com/vivaui/viva/flex"
	"github.com/vivaui/viva/ui"
	"motty/internal/i18n"
	"motty/internal/update"
)

// Where the project and its community are. A moved group or site is changed in
// one place, so the page and its help text cannot drift apart.
const (
	aboutQQURL      = "https://qm.qq.com/cgi-bin/qm/qr?k=&group_code=1131573299"
	aboutWeChatURL  = "https://docs.qq.com/doc/DVXBGYnFFdm9UWkVP"
	aboutDiscordURL = "https://discord.gg/6s5tn9H4p2"
	aboutIssuesURL  = "https://github.com/t8y2/motty/issues"
	aboutRepoURL    = "https://github.com/t8y2/motty"
	aboutDocsURL    = "https://motty.page"
	aboutVivaURL    = "https://vivaui.dev"
)

var (
	hitAboutCopyInfo = tree.ID(settingsHits, "settings-about-copy")
	hitAboutQQ       = tree.ID(settingsHits, "settings-about-qq")
	hitAboutWeChat   = tree.ID(settingsHits, "settings-about-wechat")
	hitAboutDiscord  = tree.ID(settingsHits, "settings-about-discord")
	hitAboutIssues   = tree.ID(settingsHits, "settings-about-issues")
	hitAboutRepo     = tree.ID(settingsHits, "settings-about-repo")
	hitAboutDocs     = tree.ID(settingsHits, "settings-about-docs")
	hitAboutViva     = tree.ID(settingsHits, "settings-about-viva")
)

// aboutBuildInfo is what this copy of the program is: its version, the platform
// it was built for, the Go runtime under it and the commit it came from.
type aboutBuildInfo struct {
	version     string
	versionText string // the version as the page shows it
	platform    string
	build       string // the commit and its date, or "" without one
	runtime     string
	copyText    string // the same facts as one block for a bug report
}

// aboutFacts reads the build once. The strings are made here, not on a paint,
// because a settings page repaints on every pointer move and must not allocate.
var aboutFacts = sync.OnceValue(func() aboutBuildInfo {
	info, _ := debug.ReadBuildInfo()
	return readAboutFacts(info)
})

func readAboutFacts(info *debug.BuildInfo) aboutBuildInfo {
	facts := aboutBuildInfo{
		version:  update.Current,
		platform: aboutPlatform(runtime.GOOS, runtime.GOARCH),
		runtime:  runtime.Version(),
	}
	facts.versionText = "v" + facts.version
	if info != nil {
		var revision, when string
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				revision = setting.Value
			case "vcs.time":
				when = setting.Value
			}
		}
		if len(revision) > 7 {
			revision = revision[:7]
		}
		if revision != "" {
			facts.build = revision
			if stamp, err := time.Parse(time.RFC3339, when); err == nil {
				facts.build += " · " + stamp.Format("2006-01-02")
			}
		}
	}
	facts.copyText = "Motty " + facts.version + "\nplatform: " + facts.platform + "\nruntime: " + facts.runtime + "\n"
	if facts.build != "" {
		facts.copyText += "build: " + facts.build + "\n"
	}
	return facts
}

// aboutPlatform names the operating system and architecture as a person reads
// them, while keeping the runtime's own names for anything unrecognised.
func aboutPlatform(goos, goarch string) string {
	system := goos
	switch goos {
	case "darwin":
		system = "macOS"
	case "windows":
		system = "Windows"
	case "linux":
		system = "Linux"
	case "freebsd":
		system = "FreeBSD"
	}
	switch goarch {
	case "amd64":
		goarch = "x86-64"
	case "386":
		goarch = "x86"
	}
	return system + " · " + goarch
}

// buildText names the build, with a word of its own when no commit was recorded.
func (facts aboutBuildInfo) buildText(m i18n.AboutMessages) string {
	if facts.build == "" {
		return m.BuildUnavailable
	}
	return facts.build
}

// Tiles are two to a row whenever the page is at least this wide; below it one
// tile per row keeps each one readable. The page width is known while it is
// declared, so the layout is chosen rather than approximated by a minimum cell.
const aboutTwoColumnMin = float32(460)

// tileBox is the inset grid of a group's card: rows of tiles with room between
// them. It takes the place of a row, so whatever follows it gets a hairline.
func (page *settingsPage) tileBox(children func()) {
	page.separator()
	page.f.Column().FillWidth().Pad(14).Gap(10).Children(children)
}

// pair places two tiles side by side, or one above the other when the page is
// too narrow for two.
func (page *settingsPage) pair(first, second func()) {
	if page.width < aboutTwoColumnMin {
		page.f.Column().FillWidth().Gap(10).Children(func() {
			first()
			second()
		})
		return
	}
	page.f.Row().FillWidth().Gap(10).Children(func() {
		page.f.Column().Grow(1).Basis(0).Children(first)
		page.f.Column().Grow(1).Basis(0).Children(second)
	})
}

// factTile is one fact of the build: its name above its value.
func (page *settingsPage) factTile(icon uint8, label, value string) {
	f, pal := page.f, page.state.pal
	tile := f.Column().FillWidth().Height(60).PadSides(10, 12, 10, 12).Justify(flex.Center).Gap(3).Background(pal.surfaceSoft).Radius(radius.item)
	page.matchAnchor(label, tile, 0)
	tile.Children(func() {
		f.Row().Items(flex.Center).Gap(6).Children(func() {
			f.Icon(lucideIcons[icon]).Size(14, 14).Color(pal.muted).Shrink(0)
			f.Text(label).FontSize(metrics.FontSizeS).Color(pal.muted).LineHeight(15)
		})
		f.Text(value).Mono().FontSize(metrics.FontSizeM).Color(pal.text).LineHeight(19).Ellipsis()
	})
}

// linkCard is one place to go: its name, what it is for, and a mark that it
// opens outside the window. The whole card is the target.
func (page *settingsPage) linkCard(id ui.ID, icon uint8, label, description string) {
	f, pal := page.f, page.state.pal
	background := pal.surfaceSoft
	if f.Canvas().Hovered() == id {
		background = pal.surfaceHot
	}
	border := withAlpha(pal.line, 0.85)
	if f.Canvas().Focused() == id {
		border = pal.accent
	}
	card := f.Column().FillWidth().Height(86).PadSides(12, 12, 12, 12).Gap(5).Justify(flex.Center).Background(background).Radius(radius.control).Border(1, border)
	page.matchAnchor(label, card, 0)
	page.hitOn(card, id, label, ui.HitOptions{Role: ui.RoleLink, Cursor: ui.PointerCursorHand, Description: description})
	card.Children(func() {
		f.Row().Items(flex.Center).Gap(8).Children(func() {
			f.Icon(lucideIcons[icon]).Size(16, 16).Color(pal.text).Shrink(0)
			f.Text(label).FontSize(metrics.FontSizeM).Weight(ui.WeightMedium).Color(pal.text).LineHeight(20).Grow(1)
			f.Icon(lucideIcons[iconLink]).Size(12, 12).Color(pal.faint).Shrink(0)
		})
		f.Paragraph(description, 2).FontSize(metrics.FontSizeS).Color(pal.muted).LineHeight(15)
	})
}

// vivaColophon closes the page with the framework that draws the window. It is
// not a place to go like the cards above, so it is one centered line below
// them, and the words and the mark are the whole of its target.
func (page *settingsPage) vivaColophon() {
	f, pal := page.f, page.state.pal
	m := page.state.messages
	color := pal.muted
	if f.Canvas().Hovered() == hitAboutViva || f.Canvas().Focused() == hitAboutViva {
		color = pal.accent
	}
	f.Row().FillWidth().Items(flex.Center).Justify(flex.Center).Children(func() {
		line := f.Row().Items(flex.Center).Gap(5)
		page.matchAnchor(m.About.Viva, line, 0)
		page.hitOn(line, hitAboutViva, m.About.Viva, ui.HitOptions{Role: ui.RoleLink, Cursor: ui.PointerCursorHand, Description: m.About.VivaDescription})
		line.Children(func() {
			f.Icon(lucideIcons[iconLink]).Size(11, 11).Color(color).Shrink(0)
			f.Text(m.About.Viva).FontSize(metrics.FontSizeS).Color(color).LineHeight(15)
		})
	})
}

// paintAboutSettings paints the About category: what this copy is, where to
// report a problem and where the project lives.
func (state *State) paintAboutSettings(page *settingsPage) {
	m, pal := state.messages, state.pal
	facts := aboutFacts()
	copyAction := m.About.CopyAction
	if state.settings.aboutCopied {
		copyAction = m.About.CopiedAction
	}
	page.groups(func() {
		page.group("", func() {
			// The wordmark is a picture, so it keeps a slot the page paints
			// once it is laid out, as the sidebar header does.
			row := page.f.Row().Height(96).PadX(18).Gap(16).Items(flex.Center)
			row.Children(func() {
				page.f.Column().Grow(1).Children(func() {
					page.add(settingsControl{kind: controlLogo, slot: page.f.Slot().Size(lockupWidth, lockupHeight).Shrink(0)})
					page.f.Paragraph(m.About.Tagline, 2).FontSize(metrics.FontSizeS).Color(pal.muted).LineHeight(16).MarginSides(6, 0, 0, 0)
				})
				page.button(hitAboutCopyInfo, copyAction, aiButtonOutline, false).Shrink(0)
			})
		})
		page.group(m.About.InfoTitle, func() {
			page.tileBox(func() {
				page.pair(func() {
					page.factTile(iconInfo, m.About.Version, facts.versionText)
				}, func() {
					page.factTile(iconDesktop, m.About.Platform, facts.platform)
				})
				page.pair(func() {
					page.factTile(iconWrench, m.About.Build, facts.buildText(m.About))
				}, func() {
					page.factTile(iconTerminal, m.About.Runtime, facts.runtime)
				})
			})
		})
		page.group(m.About.CommunityTitle, func() {
			page.tileBox(func() {
				page.pair(func() {
					page.linkCard(hitAboutQQ, iconQQ, m.About.QQ, m.About.QQDescription)
				}, func() {
					page.linkCard(hitAboutWeChat, iconWeChat, m.About.WeChat, m.About.WeChatDescription)
				})
				page.pair(func() {
					page.linkCard(hitAboutDiscord, iconDiscord, m.About.Discord, m.About.DiscordDescription)
				}, func() {
					page.linkCard(hitAboutIssues, iconBug, m.About.Issues, m.About.IssuesDescription)
				})
			})
		})
		page.group(m.About.ProjectTitle, func() {
			page.tileBox(func() {
				page.pair(func() {
					page.linkCard(hitAboutRepo, iconGitHub, m.About.Repo, m.About.RepoDescription)
				}, func() {
					page.linkCard(hitAboutDocs, iconGlobe, m.About.Docs, m.About.DocsDescription)
				})
			})
		})
		page.vivaColophon()
	})
}

// clickAboutSettings handles the presses of the About page. It reports whether
// the identity was one of them.
func (state *State) clickAboutSettings(id ui.ID) bool {
	switch id {
	case hitAboutCopyInfo:
		state.copyAboutInfo()
	case hitAboutQQ:
		state.openExternal(aboutQQURL)
	case hitAboutWeChat:
		state.openExternal(aboutWeChatURL)
	case hitAboutDiscord:
		state.openExternal(aboutDiscordURL)
	case hitAboutIssues:
		state.openExternal(aboutIssuesURL)
	case hitAboutRepo:
		state.openExternal(aboutRepoURL)
	case hitAboutDocs:
		state.openExternal(aboutDocsURL)
	case hitAboutViva:
		state.openExternal(aboutVivaURL)
	default:
		return false
	}
	return true
}

// copyAboutInfo puts the build's facts on the clipboard, ready to paste into a
// bug report.
func (state *State) copyAboutInfo() {
	if err := state.options.SetClipboardText(aboutFacts().copyText); err != nil {
		state.settings.aboutCopied = false
		state.status = fmt.Sprintf(state.messages.StatusClipboardFailedFmt, err)
		return
	}
	state.settings.aboutCopied = true
	state.status = state.messages.About.Copied
}
