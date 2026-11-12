package workbench

import (
	"bytes"
	"encoding/json"
	layoutcore "motty/internal/workspace"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"motty/internal/configstore"
)

func TestWorkspaceTemplatesRoundTripInStableOrder(t *testing.T) {
	path := testConfigPath(t)
	production := mustWorkspaceTemplate(t, "Production", []string{"host_b", "host_a"}, 2)
	database := mustWorkspaceTemplate(t, "Database", []string{"host_c"}, 1)
	want := savedState{WorkspaceTemplates: []WorkspaceTemplate{database, production}}
	if err := saveState(path, want); err != nil {
		t.Fatal(err)
	}
	got, report, err := loadState(path)
	if err != nil || report.outcome != loadOK {
		t.Fatalf("load: %+v, %v", report, err)
	}
	if !reflect.DeepEqual(got.WorkspaceTemplates, want.WorkspaceTemplates) {
		t.Fatalf("templates = %+v, want %+v", got.WorkspaceTemplates, want.WorkspaceTemplates)
	}
	store, err := configstore.Open(path, configFormat)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	records, err := store.Records()
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, record := range records {
		if record.Kind == kindWorkspaceTemplate && !record.Deleted {
			ids = append(ids, record.ID)
		}
	}
	if len(ids) != 2 || !slices.Contains(ids, production.ID) || !slices.Contains(ids, database.ID) {
		t.Fatalf("records = %v", ids)
	}
}

func TestLegacyWorkspaceTemplateRecordProjection(t *testing.T) {
	const id = "ws_0123456789abcdef0123456789abcdef"
	legacy := []byte(`{"o":1,"d":{"id":"` + id + `","name":"Legacy","host_ids":["host_a"],"columns":2}}`)
	projected, err := projectRecord(configstore.Key{Kind: kindWorkspaceTemplate, ID: id}, legacy)
	if err != nil {
		t.Fatalf("project legacy template: %v", err)
	}
	var payload recordPayload
	if err := json.Unmarshal(projected, &payload); err != nil {
		t.Fatal(err)
	}
	var template WorkspaceTemplate
	if err := json.Unmarshal(payload.Data, &template); err != nil {
		t.Fatal(err)
	}
	if template.ID != id || template.Columns != 2 || template.Layout.Kind != 0 {
		t.Fatalf("legacy projection = %+v", template)
	}
}

func TestLegacyWorkspaceTemplateDoesNotBlockSavingOrLaunching(t *testing.T) {
	for _, incremental := range []bool{false, true} {
		for _, action := range []string{"create", "edit", "launch"} {
			name := "full/" + action
			if incremental {
				name = "incremental/" + action
			}
			t.Run(name, func(t *testing.T) {
				world, options := newWorld(t)
				initial := newTestState(t, options)
				template := mustWorkspaceTemplate(t, "Legacy", workspaceCatalogIDs(initial, 0, 1), 2)
				raw, err := json.Marshal(map[string]any{
					"id": template.ID, "name": template.Name, "host_ids": template.HostIDs,
					"columns": 2, "future_field": true,
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := initial.config.Commit(configstore.Change{Put: []configstore.Entry{{
					Kind: kindWorkspaceTemplate, ID: template.ID, Payload: recordPayloadJSON(t, 1, raw),
				}}}); err != nil {
					t.Fatal(err)
				}
				state := newTestState(t, options)
				if len(state.templates) != 1 || !isGrid(state.templates[0].Layout, 2) {
					t.Fatalf("restored templates = %+v", state.templates)
				}
				state.activeSection = sectionWorkspaces
				state.hasSaved = incremental
				if incremental {
					state.lastSaved = state.snapshot()
				}
				switch action {
				case "create":
					state.openWorkspaceDraft(workspaceDraftFixed)
					state.workspaceDraft.name.Insert("New template")
					state.workspaceDraft.selected[template.HostIDs[0]] = true
					state.submitWorkspaceDraft()
					if len(state.templates) != 2 || state.workspaceDraft.error != "" {
						t.Fatalf("create failed: templates=%d error=%q status=%q",
							len(state.templates), state.workspaceDraft.error, state.status)
					}
				case "edit":
					state.openWorkspaceDraftEdit(template.ID)
					state.workspaceDraft.name.Insert("Renamed")
					state.submitWorkspaceDraft()
					if state.templates[0].Name != "Renamed" || state.workspaceDraft.error != "" {
						t.Fatalf("edit failed: template=%+v error=%q status=%q",
							state.templates[0], state.workspaceDraft.error, state.status)
					}
				case "launch":
					state.selectedWorkspaceTemplateID = template.ID
					state.applySelectedWorkspaceTemplate()
					if len(world.configs) != 2 || state.activeSection != sectionTerminal {
						t.Fatalf("launch failed: dials=%d section=%d status=%q",
							len(world.configs), state.activeSection, state.status)
					}
				}
				restored := newTestState(t, options)
				if !reflect.DeepEqual(restored.templates, state.templates) {
					t.Fatalf("saved templates = %+v, want %+v", restored.templates, state.templates)
				}
				if action == "launch" && (len(restored.sessions) != 2 ||
					!restored.workspaceManaged(restored.deck.ActiveWorkspace())) {
					t.Fatal("launched workspace did not survive a restart")
				}
				records, err := state.config.Records()
				if err != nil {
					t.Fatal(err)
				}
				for _, record := range records {
					if record.Kind == kindWorkspaceTemplate && record.ID == template.ID &&
						!bytes.Contains(record.Payload, []byte(`"future_field":true`)) {
						t.Fatalf("save lost an unknown template field: %s", record.Payload)
					}
				}
			})
		}
	}
}

func TestAMalformedWorkspaceTemplateDoesNotBlockTheOthers(t *testing.T) {
	path := testConfigPath(t)
	valid := mustWorkspaceTemplate(t, "Good", []string{"host_a"}, 1)
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	invalidID, err := newWorkspaceTemplateID()
	if err != nil {
		t.Fatal(err)
	}
	var invalid WorkspaceTemplate
	invalid = WorkspaceTemplate{ID: invalidID, Name: "Bad", HostIDs: []string{"host_a", "host_a"}, Layout: layoutcore.GridSpec(1)}
	bad, err := json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	store, err := configstore.Open(path, configFormat)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(configstore.Change{Put: []configstore.Entry{
		{Kind: kindWorkspaceTemplate, ID: valid.ID, Payload: recordPayloadJSON(t, 1, raw)},
		{Kind: kindWorkspaceTemplate, ID: invalid.ID, Payload: recordPayloadJSON(t, 2, bad)},
	}}); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	got, report, err := loadState(path)
	if err != nil || report.outcome != loadOK {
		t.Fatalf("load: %+v, %v", report, err)
	}
	if !reflect.DeepEqual(got.WorkspaceTemplates, []WorkspaceTemplate{valid}) {
		t.Fatalf("templates = %+v", got.WorkspaceTemplates)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("the malformed record moved the database aside")
	}
}

// A store from before layouts existed holds a template with only a grid width.
// Reading it must not make every save fail: a save re-encodes the record it
// finds, and a template with no layout has no kind to name.
func TestLegacyWorkspaceTemplateRecordDoesNotBlockSaving(t *testing.T) {
	path := testConfigPath(t)
	if err := saveState(path, savedState{Hosts: sampleHosts}); err != nil {
		t.Fatal(err)
	}
	id, err := newWorkspaceTemplateID()
	if err != nil {
		t.Fatal(err)
	}
	legacy := []byte(`{"id":"` + id + `","name":"Legacy","host_ids":["host_a"],"columns":2}`)
	store, err := configstore.Open(path, configFormat)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(configstore.Change{Put: []configstore.Entry{
		{Kind: kindWorkspaceTemplate, ID: id, Payload: recordPayloadJSON(t, 1, legacy)},
	}}); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	options := freshOptions(t)
	options.StatePath = path
	state := newTestState(t, options)
	if len(state.templates) != 1 || !isGrid(state.templates[0].Layout, 2) {
		t.Fatalf("a legacy template loaded as %+v", state.templates)
	}
	if err := state.saveWithResult(); err != nil {
		t.Fatalf("the save the legacy record blocked: %v", err)
	}
	got, report, err := loadState(path)
	if err != nil || report.outcome != loadOK {
		t.Fatalf("load: %+v, %v", report, err)
	}
	if len(got.WorkspaceTemplates) != 1 || got.WorkspaceTemplates[0].ID != id || !isGrid(got.WorkspaceTemplates[0].Layout, 2) {
		t.Fatalf("templates after the save = %+v", got.WorkspaceTemplates)
	}
}

func TestLoadedWorkspaceTemplateKeepsItsNormalizedValues(t *testing.T) {
	_, options := newWorld(t)
	valid := mustWorkspaceTemplate(t, "Good", []string{"host_a"}, 1)
	valid.Name = " Padded "
	valid.HostIDs = []string{" host_a "}
	if err := saveState(options.StatePath, savedState{Hosts: sampleHosts, WorkspaceTemplates: []WorkspaceTemplate{valid}}); err != nil {
		t.Fatal(err)
	}
	state := newTestState(t, options)
	if len(state.templates) != 1 || state.templates[0].Name != "Padded" ||
		!slices.Equal(state.templates[0].HostIDs, []string{"host_a"}) {
		var validation error
		if len(state.templates) == 1 {
			validation = state.templates[0].Validate()
		}
		t.Fatalf("restored template = %#v, validation=%v", state.templates, validation)
	}
}

func TestAnOlderBuildKeepsWorkspaceTemplateRecords(t *testing.T) {
	path := testConfigPath(t)
	template := mustWorkspaceTemplate(t, "Production", []string{"host_a"}, 1)
	if err := saveState(path, savedState{WorkspaceTemplates: []WorkspaceTemplate{template}}); err != nil {
		t.Fatal(err)
	}
	entries, local, err := configstore.ReadOnly(path, configFormat)
	if err != nil {
		t.Fatal(err)
	}
	base := newConfigBase()
	var saved savedState
	for _, entry := range entries {
		if entry.Kind != kindWorkspaceTemplate {
			continue
		}
		base.payloads[configstore.Key{Kind: entry.Kind, ID: entry.ID}] = entry.Payload
	}
	saved.Version, saved.HostCatalogVersion, saved.ShortcutVersion = stateFileVersion, hostCatalogSchemaVersion, shortcutSchemaVersion
	if _, _, _, err := splitState(saved, base, nil); err == nil {
		base.local = local[localKey]
		store, err := configstore.Open(path, configFormat)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Commit(configstore.Change{Put: []configstore.Entry{
			{Kind: kindSetting, ID: "terminal_scrollback", Payload: []byte(`{"d":10000}`)},
		}}); err != nil {
			store.Close()
			t.Fatal(err)
		}
		store.Close()
	}
	// A full save from a state that never decoded the new field must not delete
	// the record. This is the older build's behavior through the unknown-kind
	// retention path.
	got, _, err := loadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.WorkspaceTemplates) != 1 || got.WorkspaceTemplates[0].ID != template.ID {
		t.Fatalf("templates after older save = %+v", got.WorkspaceTemplates)
	}
}

func mustWorkspaceTemplate(t testing.TB, name string, hosts []string, columns uint8) WorkspaceTemplate {
	t.Helper()
	template, err := NewWorkspaceTemplate(name, hosts, columnsSpec(columns))
	if err != nil {
		t.Fatal(err)
	}
	return template
}

func testConfigPath(t testing.TB) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "config.db")
}

func recordPayloadJSON(t testing.TB, ord int64, data []byte) []byte {
	t.Helper()
	payload, err := json.Marshal(recordPayload{Ord: ord, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
