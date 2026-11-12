package workbench

import "testing"

// A host kept to its interactive session is off until the user or a refusing
// server turns it on, and the choice survives a restart: a gateway that permits
// only an interactive login must not be asked for probes again.
func TestInteractiveOnlyIsOffUntilSwitchedOnAndSurvivesARestart(t *testing.T) {
	state := newTestState(t, testOptions(t))
	state.Click(hitAddHost)
	state.editor.label.Insert("Gateway")
	state.editor.address.Insert("gateway.example.com")
	state.Click(hitDialogSubmit)
	find := func(s *State) Host {
		for _, host := range s.hosts {
			if host.Label == "Gateway" {
				return host
			}
		}
		t.Fatal("host missing")
		return Host{}
	}
	if find(state).InteractiveOnly {
		t.Fatal("a new host was confined to its interactive session")
	}

	state.selectedHostID = find(state).ID
	state.openEditHost()
	state.Click(hitDialogInteractiveOnly)
	state.Click(hitDialogSendLocale)
	if !state.editor.interactiveOnly {
		t.Fatal("the switch did not turn on")
	}
	state.Click(hitDialogSubmit)
	if !find(state).InteractiveOnly {
		t.Fatal("the choice was not saved")
	}
	if !find(state).SendLocale {
		t.Fatal("the locale choice was not saved")
	}
	again := New(state.options)
	defer again.Close()
	if !find(again).InteractiveOnly {
		t.Fatal("the choice did not survive a restart")
	}
	if !find(again).SendLocale {
		t.Fatal("the locale choice did not survive a restart")
	}
}
