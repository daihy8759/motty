package completion

import (
	"fmt"
	"strings"
	"testing"
)

func importFiles(t *testing.T, files []SourceFile, opts ImportOptions) (*Catalog, ImportStats) {
	t.Helper()
	meta := Metadata{Source: "test", Release: "v1", Commit: "abcdef", License: "MIT"}
	catalog, stats, err := Import(files, meta, opts)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	return catalog, stats
}

func TestImportCommandTree(t *testing.T) {
	files := []SourceFile{
		{Name: "git/git.yaml", Data: []byte(`
name: git <tree-ish>
description: the stupid content tracker
aliases: [g]
flags:
  --color=: when to use colors
  -C=: run as if started in path
  --hidden&: not offered
  --broken~: unsupported modifier
  -P, --no-pager: do not pipe output
persistentflags:
  --version: print version
completion:
  flag:
    color:
      - always
      - auto	"pick" the mode
      - $Dynamic
      - "unsafe value"
`)},
		{Name: "git/git.commit.yaml", Data: []byte(`
name: commit [options]
description: record changes
commands:
  - name: amend
    description: amend the previous commit
`)},
		{Name: "git/git.bogus.yaml", Data: []byte(`
name: other
description: mismatched name
`)},
	}
	catalog, stats := importFiles(t, files, ImportOptions{})
	if catalog.RootCount() != 1 || catalog.NodeCount() != 3 {
		t.Fatalf("roots=%d nodes=%d, want 1 and 3", catalog.RootCount(), catalog.NodeCount())
	}
	if stats.SkippedFiles != 1 || stats.SkippedFlags == 0 || stats.SkippedValues == 3 || stats.HiddenFlags != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	git := catalog.Root("g")
	if git == nil || git.Token != "git" {
		t.Fatalf("root alias did not resolve: %+v", git)
	}
	color, ok := catalog.FindFlag(git, "--color")
	if !ok || !color.Value || len(color.Values) != 2 {
		t.Fatalf("--color = %+v, %v", color, ok)
	}
	if color.Values[1].Text != "auto" || color.Values[1].Desc != `"pick" the mode` {
		t.Fatalf("value description = %+v", color.Values[1])
	}
	if _, ok := catalog.FindFlag(git, "--hidden"); ok {
		t.Fatal("hidden flag was imported")
	}
	commit := catalog.Lookup([]string{"git", "commit"})
	if commit == nil || commit.Desc != "record changes" {
		t.Fatalf("git commit = %+v", commit)
	}
	amend := catalog.Lookup([]string{"git", "commit", "amend"})
	if amend == nil || amend.Desc != "amend the previous commit" {
		t.Fatalf("git commit amend = %+v", amend)
	}
	if catalog.Lookup([]string{"git", "bogus"}) != nil {
		t.Fatal("a file whose name disagrees with its path was imported")
	}
}

func TestImportSkipsRootlessDirectories(t *testing.T) {
	files := []SourceFile{
		{Name: "orphan/orphan.child.yaml", Data: []byte("name: child\ndescription: child\n")},
	}
	_, stats, err := Import(files, Metadata{Source: "s", Commit: "c", License: "MIT"}, ImportOptions{})
	if err == nil {
		t.Fatal("a catalog without roots was accepted")
	}
	if stats.RootlessDirs != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestImportRequiresMetadata(t *testing.T) {
	files := []SourceFile{{Name: "a/a.yaml", Data: []byte("name: a\n")}}
	_, _, err := Import(files, Metadata{Source: "s", License: "MIT"}, ImportOptions{})
	if err == nil {
		t.Fatal("missing commit was accepted")
	}
}

func TestImportBoundsFileSize(t *testing.T) {
	files := []SourceFile{{Name: "a/a.yaml", Data: []byte("name: a\n")}}
	_, _, err := Import(files, Metadata{Source: "s", Commit: "c", License: "MIT"}, ImportOptions{MaxFileBytes: 4})
	if err == nil {
		t.Fatal("a catalog without roots was accepted")
	}
	if !strings.Contains(err.Error(), "a/a.yaml") {
		t.Fatalf("error lost source path: %v", err)
	}
}

func TestParseFlagSpec(t *testing.T) {
	cases := []struct {
		spec   string
		flag   Flag
		hidden bool
		ok     bool
	}{
		{"--all", Flag{Long: "all"}, false, true},
		{"-a, --all", Flag{Long: "all", Short: "a"}, false, true},
		{"-a", Flag{Short: "a"}, false, true},
		{"--color=", Flag{Long: "color", Value: true}, false, true},
		{"--color?", Flag{Long: "color", Value: true, Optional: true}, false, true},
		{"--tag=*", Flag{Long: "tag", Value: true, Repeatable: true}, false, true},
		{"--file=!", Flag{Long: "file", Value: true, Required: true}, false, true},
		{"--secret&", Flag{Long: "secret"}, true, true},
		{"--bad~", Flag{}, false, false},
		{"--", Flag{}, false, false},
		{"-a, -b", Flag{}, false, false},
	}
	for _, c := range cases {
		flag, hidden, ok := parseFlagSpec(c.spec)
		if ok != c.ok {
			t.Errorf("%q ok=%v, want %v", c.spec, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if flag.Long != c.flag.Long || flag.Short != c.flag.Short || flag.Value != c.flag.Value ||
			flag.Optional != c.flag.Optional || flag.Repeatable != c.flag.Repeatable || flag.Required != c.flag.Required {
			t.Errorf("%q = %+v, want %+v", c.spec, flag, c.flag)
		}
		if hidden != c.hidden {
			t.Errorf("%q hidden=%v, want %v", c.spec, hidden, c.hidden)
		}
	}
}

func TestImportValueBounds(t *testing.T) {
	values := make([]string, 0, maxValuesPerFlag+5)
	for i := 0; i < maxValuesPerFlag+5; i++ {
		values = append(values, fmt.Sprintf("value%d", i))
	}
	data := "name: a\nflags:\n  --mode=: mode\ncompletion:\n  flag:\n    mode:\n"
	for _, value := range values {
		data += "      - " + value + "\n"
	}
	catalog, stats := importFiles(t, []SourceFile{{Name: "a/a.yaml", Data: []byte(data)}}, ImportOptions{})
	flag, _ := catalog.FindFlag(catalog.Root("a"), "--mode")
	if len(flag.Values) != maxValuesPerFlag {
		t.Fatalf("values = %d, want %d", len(flag.Values), maxValuesPerFlag)
	}
	if stats.SkippedValues == 0 {
		t.Fatal("overflowing values were not counted")
	}
}

func TestImportRejectsStructuralErrors(t *testing.T) {
	for name, data := range map[string]string{
		"invalid flag list":    "name: child\nflags: [not-a-map]\n",
		"invalid scalar flags": "name: child\nflags: unexpected\n",
		"invalid description":  "name: child\nflags:\n  --all: [bad]\n",
		"invalid command":      "name: child\ncommands: [bad]\n",
		"invalid yaml":         "name: child\nflags:\n  --all: invalid: description\n",
		"empty yaml":           "",
		"null root":            "null",
		"second document":      "name: child\n---\nflags: [bad]\n",
	} {
		t.Run(name, func(t *testing.T) {
			files := []SourceFile{{Name: "a/a.yaml", Data: []byte("name: a\n")}, {Name: "a/a.child.yaml", Data: []byte(data)}}
			if _, _, err := Import(files, Metadata{Source: "s", Commit: "c", License: "MIT"}, ImportOptions{}); err == nil {
				t.Fatal("partial catalog accepted after a structural source error")
			}
		})
	}
}

func TestImportStructuredFlagDescription(t *testing.T) {
	catalog, _ := importFiles(t, []SourceFile{{Name: "wt/wt.yaml", Data: []byte("name: wt\nflags:\n  --format=:\n    description: Output format\n    default: text\ncompletion:\n  flag:\n    format: [text, json]\n")}}, ImportOptions{})
	flag, ok := catalog.FindFlag(catalog.Root("wt"), "--format")
	if !ok || flag.Desc != "Output format" || len(flag.Values) != 2 {
		t.Fatalf("structured flag = %+v, found=%v", flag, ok)
	}
}

func TestImportRejectsOversizedChild(t *testing.T) {
	files := []SourceFile{{Name: "a/a.yaml", Data: []byte("name: a\n")}, {Name: "a/a.child.yaml", Data: []byte("name: child\ndescription: too long\n")}}
	if _, _, err := Import(files, Metadata{Source: "s", Commit: "c", License: "MIT"}, ImportOptions{MaxFileBytes: 12}); err == nil {
		t.Fatal("oversized child was silently dropped")
	}
}

func TestImportRejectsChildDecodeLimits(t *testing.T) {
	files := []SourceFile{{Name: "a/a.yaml", Data: []byte("name: a\n")}, {Name: "a/a.child.yaml", Data: []byte("name: child\nflags:\n  --format=:\n    description: Output\n")}}
	for _, opts := range []ImportOptions{{MaxYAMLNodes: 8}, {MaxYAMLDepth: 3}} {
		if _, _, err := Import(files, Metadata{Source: "s", Commit: "c", License: "MIT"}, opts); err == nil || !strings.Contains(err.Error(), "a/a.child.yaml") {
			t.Fatalf("decode limit did not reject child with its path: %v", err)
		}
	}
}

func TestImportRejectsDuplicateSource(t *testing.T) {
	files := []SourceFile{{Name: "a/a.yaml", Data: []byte("name: a\n")}, {Name: "a/a.yaml", Data: []byte("name: a\ndescription: overwritten\n")}}
	if _, _, err := Import(files, Metadata{Source: "s", Commit: "c", License: "MIT"}, ImportOptions{}); err == nil {
		t.Fatal("duplicate source silently replaced a definition")
	}
}

func TestImportRejectsCommandDepthLimit(t *testing.T) {
	for name, file := range map[string]SourceFile{
		"file path":      {Name: "a/a." + strings.Repeat("child.", maxDepth) + "last.yaml", Data: []byte("name: last\n")},
		"nested command": {Name: "a/a." + strings.Repeat("child.", maxDepth-2) + "last.yaml", Data: []byte("name: last\ncommands:\n  - name: nested\n")},
	} {
		t.Run(name, func(t *testing.T) {
			files := []SourceFile{{Name: "a/a.yaml", Data: []byte("name: a\n")}, file}
			if _, _, err := Import(files, Metadata{Source: "s", Commit: "c", License: "MIT"}, ImportOptions{}); err == nil {
				t.Fatal("deep command was silently skipped")
			}
		})
	}
}

func TestImportAllowsFileAtSizeLimit(t *testing.T) {
	data := []byte("name: a\n")
	catalog, _ := importFiles(t, []SourceFile{{Name: "a/a.yaml", Data: data}}, ImportOptions{MaxFileBytes: len(data)})
	if catalog.Root("a") == nil {
		t.Fatal("source exactly at size limit was rejected")
	}
}
