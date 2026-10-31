package workbench

import (
	"fmt"
	"testing"

	"github.com/vivaui/viva/text"
)

// addHostAtSharedEndpoint adds a new host with the same destination as source,
// so it is a second entry at one endpoint, and returns it.
func addHostAtSharedEndpoint(t *testing.T, state *State, source Host, label string, configure func(*State)) Host {
	t.Helper()
	state.Click(hitAddHost)
	typeInto(state, hitDialogLabel, label)
	typeInto(state, hitDialogAddress, source.Address)
	typeInto(state, hitDialogUser, source.User)
	state.editor.port = text.Editor{}
	state.editor.port.Insert(fmt.Sprint(source.Port))
	if configure != nil {
		configure(state)
	}
	state.Click(hitDialogSubmit)
	if state.modal != modalNone || state.dialogError != "" {
		t.Fatalf("adding host %q at a shared endpoint: modal=%d error=%q", label, state.modal, state.dialogError)
	}
	added := state.hosts[len(state.hosts)-1]
	if added.Address != source.Address || added.User != source.User || added.Port != source.Port {
		t.Fatalf("added endpoint = %+v, source = %+v", added, source)
	}
	if added.CatalogID == source.CatalogID {
		t.Fatalf("added host reused catalog id %q", source.CatalogID)
	}
	return added
}

// A restored tab belongs to the exact saved host it was opened from, even when
// another host shares its endpoint.
func TestSessionsRestoreToTheirOwnSharedEndpointHost(t *testing.T) {
	_, options := newWorld(t)
	first := newTestState(t, options)
	production := first.hosts[0]
	alt := addHostAtSharedEndpoint(t, first, production, "Production alt", func(state *State) {
		state.editor.loginExpect = *sampleLoginExpect()
		state.editor.auth = authAgent
	})

	first.Click(hitHosts)
	first.Click(hitHostList.At(int(production.ID)))
	openHost(first)
	first.Click(hitHosts)
	first.Click(hitHostList.At(int(alt.ID)))
	openHost(first)
	if len(first.sessions) != 2 {
		t.Fatalf("opened sessions = %d", len(first.sessions))
	}
	want := map[string]string{production.Label: production.CatalogID, alt.Label: alt.CatalogID}
	first.save()

	second := newTestState(t, options)
	if len(second.sessions) != 2 {
		t.Fatalf("restored sessions = %+v", second.sessions)
	}
	seen := map[string]bool{}
	for _, session := range second.sessions {
		if session.isLocal() {
			continue
		}
		catalog, ok := want[session.Title]
		if !ok || session.host.CatalogID != catalog {
			t.Fatalf("restored session %q bound to %q, want %q", session.Title, session.host.CatalogID, catalog)
		}
		seen[session.Title] = true
		if session.Title == alt.Label && (session.host.LoginExpect == nil || session.host.Auth != authAgent) {
			t.Fatalf("restored alt session lost its host settings: %+v", session.host)
		}
	}
	if !seen[production.Label] || !seen[alt.Label] {
		t.Fatalf("restored sessions = %+v", second.sessions)
	}
}

// A tab whose saved host id no longer exists is not rebound to a same-endpoint
// namesake; an old record without an id still falls back to its endpoint.
func TestRestoredSessionWithMissingHostIsDroppedNotRebound(t *testing.T) {
	state := newTestState(t, testOptions(t))
	production := state.hosts[0]

	missing := savedSession{Label: "Gone", Address: production.Address, User: production.User, Port: production.Port, SavedHost: true, HostID: "host_missing"}
	if host, ok := state.restoreSessionHost(missing); ok {
		t.Fatalf("a session with a missing host id bound to %+v", host)
	}
	old := savedSession{Label: "Old", Address: production.Address, User: production.User, Port: production.Port, SavedHost: true}
	host, ok := state.restoreSessionHost(old)
	if !ok || host.CatalogID != production.CatalogID {
		t.Fatalf("an old record without an id restored %+v, %v", host, ok)
	}
}

// Proxy routes remember their exact ends, so a second host at one endpoint does
// not steal the target or jump of another route.
func TestProxiesRestoreToTheirOwnSharedEndpointHosts(t *testing.T) {
	options := testOptions(t)
	state := newTestState(t, options)
	production := state.hosts[0]
	router := state.hosts[2]
	altTarget := addHostAtSharedEndpoint(t, state, production, "Production alt", nil)
	altJump := addHostAtSharedEndpoint(t, state, router, "Router alt", nil)

	state.proxies = append(state.proxies, proxyRecord{ID: 1, TargetID: altTarget.ID, JumpID: altJump.ID})
	state.nextProxyID = 2
	state.save()

	restarted := newTestState(t, options)
	if len(restarted.proxies) != 1 {
		t.Fatalf("restored proxies = %+v", restarted.proxies)
	}
	route := restarted.proxies[0]
	target, targetOK := restarted.hostByID(route.TargetID)
	jump, jumpOK := restarted.hostByID(route.JumpID)
	if !targetOK || target.CatalogID != altTarget.CatalogID {
		t.Fatalf("restored target = %+v, want catalog %q", target, altTarget.CatalogID)
	}
	if !jumpOK || jump.CatalogID != altJump.CatalogID {
		t.Fatalf("restored jump = %+v, want catalog %q", jump, altJump.CatalogID)
	}
}

// A forward stays with the host it was created for when two hosts share an
// endpoint, across a restart and when the other entry is edited.
func TestForwardKeepsItsOwnSharedEndpointHost(t *testing.T) {
	_, options := newWorld(t)
	state := newTestState(t, options)
	production := state.hosts[0]
	alt := addHostAtSharedEndpoint(t, state, production, "Production alt", nil)

	state.selectedHostID = alt.ID
	state.hostSelections = nil
	addForwardRule(t, state, "Web", freePort(t), "web.internal", 8080)
	if len(state.forwards) != 1 || state.forwards[0].HostCatalogID != alt.CatalogID {
		t.Fatalf("created forward = %+v", state.forwards)
	}

	restarted := newTestState(t, options)
	if len(restarted.forwards) != 1 {
		t.Fatalf("restored forwards = %+v", restarted.forwards)
	}
	forward := restarted.forwards[0]
	if forward.HostCatalogID != alt.CatalogID || forward.HostLabel != alt.Label {
		t.Fatalf("restored forward = %+v, want host %q", forward, alt.CatalogID)
	}
	if bound, ok := restarted.forwardHost(forward); !ok || bound.CatalogID != alt.CatalogID {
		t.Fatalf("restored forward bound to %+v, %v", bound, ok)
	}

	// Editing the other entry at the same endpoint must not retarget the forward.
	restarted.openEditHostID(production.ID)
	restarted.editor.label = text.Editor{}
	typeInto(restarted, hitDialogLabel, "Production renamed")
	restarted.Click(hitDialogSubmit)
	if restarted.modal != modalNone {
		t.Fatalf("editing the namesake host failed: %q", restarted.dialogError)
	}
	if restarted.forwards[0].HostCatalogID != alt.CatalogID || restarted.forwards[0].HostLabel != alt.Label {
		t.Fatalf("editing the namesake changed the forward: %+v", restarted.forwards[0])
	}
}
