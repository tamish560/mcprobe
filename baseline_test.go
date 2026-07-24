package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadBaseline(t *testing.T) {
	snap := &ServerSnapshot{
		Info:  ServerInfo{Name: "test", Version: "1.0"},
		Tools: []Tool{{Name: "read", Description: "read stuff"}},
	}
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := SaveBaseline(snap, path); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}
	loaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if loaded.ServerName != "test" {
		t.Errorf("expected test, got %s", loaded.ServerName)
	}
	if loaded.Snapshot.Info.Version != "1.0" {
		t.Errorf("expected 1.0, got %s", loaded.Snapshot.Info.Version)
	}
	if len(loaded.Snapshot.Tools) != 1 {
		t.Errorf("expected 1 tool, got %d", len(loaded.Snapshot.Tools))
	}
	if loaded.Hash == "" {
		t.Error("expected non-empty hash")
	}
}

func TestLoadBaselineMissing(t *testing.T) {
	_, err := LoadBaseline("/nonexistent/baseline.json")
	if err == nil {
		t.Error("expected error")
	}
}

func TestB_ToolsRemoved(t *testing.T) {
	old := &ServerSnapshot{Tools: []Tool{{Name: "a"}, {Name: "b"}}}
	new := &ServerSnapshot{Tools: []Tool{{Name: "a"}}}
	diffs := DiffSnapshots(old, new)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].Type != "tool-removed" {
		t.Errorf("expected tool-removed, got %s", diffs[0].Type)
	}
	if diffs[0].Severity != "HIGH" {
		t.Errorf("expected HIGH, got %s", diffs[0].Severity)
	}
}

func TestB_ToolsAdded(t *testing.T) {
	old := &ServerSnapshot{Tools: []Tool{{Name: "a"}}}
	new := &ServerSnapshot{Tools: []Tool{{Name: "a"}, {Name: "b"}}}
	diffs := DiffSnapshots(old, new)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].Type != "tool-added" {
		t.Errorf("expected tool-added, got %s", diffs[0].Type)
	}
}

func TestB_DescriptionChanged(t *testing.T) {
	old := &ServerSnapshot{Tools: []Tool{{Name: "a", Description: "old"}}}
	new := &ServerSnapshot{Tools: []Tool{{Name: "a", Description: "new"}}}
	diffs := DiffSnapshots(old, new)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].Type != "tool-description-changed" {
		t.Errorf("expected tool-description-changed, got %s", diffs[0].Type)
	}
	if diffs[0].Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL, got %s", diffs[0].Severity)
	}
}

func TestB_SchemaChanged(t *testing.T) {
	old := &ServerSnapshot{Tools: []Tool{{Name: "a", InputSchema: map[string]interface{}{"type": "object"}}}}
	new := &ServerSnapshot{Tools: []Tool{{Name: "a", InputSchema: map[string]interface{}{"type": "string"}}}}
	diffs := DiffSnapshots(old, new)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].Type != "tool-schema-changed" {
		t.Errorf("expected tool-schema-changed, got %s", diffs[0].Type)
	}
}

func TestB_VersionChanged(t *testing.T) {
	old := &ServerSnapshot{Info: ServerInfo{Version: "1.0"}}
	new := &ServerSnapshot{Info: ServerInfo{Version: "2.0"}}
	diffs := DiffSnapshots(old, new)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].Type != "version-changed" {
		t.Errorf("expected version-changed, got %s", diffs[0].Type)
	}
}

func TestB_PromptChanges(t *testing.T) {
	old := &ServerSnapshot{Prompts: []Prompt{{Name: "p1"}}}
	new := &ServerSnapshot{Prompts: []Prompt{{Name: "p2"}}}
	diffs := DiffSnapshots(old, new)
	if len(diffs) != 2 {
		t.Fatalf("expected 2 diffs, got %d", len(diffs))
	}
}

func TestB_ResourceChanges(t *testing.T) {
	old := &ServerSnapshot{Resources: []Resource{{URI: "r1", Description: "old"}}}
	new := &ServerSnapshot{Resources: []Resource{{URI: "r1", Description: "new"}, {URI: "r2"}}}
	diffs := DiffSnapshots(old, new)
	if len(diffs) != 2 {
		t.Fatalf("expected 2 diffs, got %d", len(diffs))
	}
}

func TestB_Identical(t *testing.T) {
	snap := &ServerSnapshot{
		Info:  ServerInfo{Name: "s", Version: "1"},
		Tools: []Tool{{Name: "a", Description: "d"}},
	}
	diffs := DiffSnapshots(snap, snap)
	if len(diffs) != 0 {
		t.Errorf("expected 0 diffs, got %d", len(diffs))
	}
}

func TestSchemaEqual(t *testing.T) {
	a := map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}
	b := map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}
	c := map[string]interface{}{"type": "string"}
	if !schemaEqual(a, b) {
		t.Error("expected equal")
	}
	if schemaEqual(a, c) {
		t.Error("expected not equal")
	}
}

func TestHashSnapshot(t *testing.T) {
	snap := &ServerSnapshot{Info: ServerInfo{Name: "test"}}
	h := hashSnapshot(snap)
	if h == "" {
		t.Error("expected non-empty hash")
	}
	h2 := hashSnapshot(snap)
	if h != h2 {
		t.Error("expected same hash for same snapshot")
	}
}

func TestFormatDiff(t *testing.T) {
	d := Diff{Severity: "HIGH", Type: "tool-removed", Tool: "read", Detail: "gone"}
	out := formatDiff(d)
	if out == "" {
		t.Error("expected non-empty")
	}
}

func TestFormatDiffNoTool(t *testing.T) {
	d := Diff{Severity: "LOW", Type: "version-changed", Detail: "changed"}
	out := formatDiff(d)
	if out == "" {
		t.Error("expected non-empty")
	}
}

func TestSaveBaselineCreatesFile(t *testing.T) {
	snap := &ServerSnapshot{Info: ServerInfo{Name: "x", Version: "1"}}
	path := filepath.Join(t.TempDir(), "b.json")
	SaveBaseline(snap, path)
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected file: %v", err)
	}
}

func TestSimpleHash(t *testing.T) {
	h1 := simpleHash([]byte("test"))
	h2 := simpleHash([]byte("test"))
	if h1 != h2 {
		t.Error("expected same hash for same input")
	}
	h3 := simpleHash([]byte("different"))
	if h1 == h3 {
		t.Error("expected different hash for different input")
	}
}
