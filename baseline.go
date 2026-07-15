package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type Baseline struct {
	ServerName  string          `json:"serverName"`
	CreatedAt   string          `json:"createdAt"`
	Snapshot    ServerSnapshot  `json:"snapshot"`
	Hash        string          `json:"hash"`
}

type Diff struct {
	Type     string `json:"type"`
	Tool     string `json:"tool"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"`
}

func SaveBaseline(snap *ServerSnapshot, path string) error {
	baseline := Baseline{
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Snapshot:  *snap,
		Hash:      hashSnapshot(snap),
	}
	if snap.Info.Name != "" {
		baseline.ServerName = snap.Info.Name
	}

	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}
	return &baseline, nil
}

func DiffSnapshots(old, new *ServerSnapshot) []Diff {
	var diffs []Diff

	oldTools := make(map[string]Tool)
	for _, t := range old.Tools {
		oldTools[t.Name] = t
	}
	newTools := make(map[string]Tool)
	for _, t := range new.Tools {
		newTools[t.Name] = t
	}

	for name := range oldTools {
		if _, exists := newTools[name]; !exists {
			diffs = append(diffs, Diff{
				Type:     "tool-removed",
				Tool:     name,
				Detail:   fmt.Sprintf("Tool '%s' was removed from the server", name),
				Severity: "HIGH",
			})
		}
	}

	for name, newT := range newTools {
		oldT, exists := oldTools[name]
		if !exists {
			diffs = append(diffs, Diff{
				Type:     "tool-added",
				Tool:     name,
				Detail:   fmt.Sprintf("Tool '%s' was added to the server", name),
				Severity: "MEDIUM",
			})
			continue
		}
		if oldT.Description != newT.Description {
			diffs = append(diffs, Diff{
				Type:     "tool-description-changed",
				Tool:     name,
				Detail:   fmt.Sprintf("Tool '%s' description changed (potential rug-pull)", name),
				Severity: "CRITICAL",
			})
		}

		if !schemaEqual(oldT.InputSchema, newT.InputSchema) {
			diffs = append(diffs, Diff{
				Type:     "tool-schema-changed",
				Tool:     name,
				Detail:   fmt.Sprintf("Tool '%s' input schema changed", name),
				Severity: "HIGH",
			})
		}
	}

	oldPrompts := make(map[string]Prompt)
	for _, p := range old.Prompts {
		oldPrompts[p.Name] = p
	}
	newPrompts := make(map[string]Prompt)
	for _, p := range new.Prompts {
		newPrompts[p.Name] = p
	}

	for name := range oldPrompts {
		if _, exists := newPrompts[name]; !exists {
			diffs = append(diffs, Diff{
				Type:     "prompt-removed",
				Tool:     name,
				Detail:   fmt.Sprintf("Prompt '%s' was removed", name),
				Severity: "LOW",
			})
		}
	}
	for name := range newPrompts {
		if _, exists := oldPrompts[name]; !exists {
			diffs = append(diffs, Diff{
				Type:     "prompt-added",
				Tool:     name,
				Detail:   fmt.Sprintf("Prompt '%s' was added", name),
				Severity: "LOW",
			})
		}
	}

	oldResources := make(map[string]Resource)
	for _, r := range old.Resources {
		oldResources[r.URI] = r
	}
	newResources := make(map[string]Resource)
	for _, r := range new.Resources {
		newResources[r.URI] = r
	}
	for uri := range oldResources {
		if _, exists := newResources[uri]; !exists {
			diffs = append(diffs, Diff{
				Type:     "resource-removed",
				Tool:     uri,
				Detail:   fmt.Sprintf("Resource '%s' was removed", uri),
				Severity: "MEDIUM",
			})
		}
	}
	for uri, newR := range newResources {
		oldR, exists := oldResources[uri]
		if !exists {
			diffs = append(diffs, Diff{
				Type:     "resource-added",
				Tool:     uri,
				Detail:   fmt.Sprintf("Resource '%s' was added", uri),
				Severity: "MEDIUM",
			})
			continue
		}
		if oldR.Description != newR.Description {
			diffs = append(diffs, Diff{
				Type:     "resource-changed",
				Tool:     uri,
				Detail:   fmt.Sprintf("Resource '%s' description changed", uri),
				Severity: "MEDIUM",
			})
		}
	}

	if old.Info.Version != new.Info.Version {
		diffs = append(diffs, Diff{
			Type:     "version-changed",
			Tool:     "",
			Detail:   fmt.Sprintf("Server version changed from '%s' to '%s'", old.Info.Version, new.Info.Version),
			Severity: "LOW",
		})
	}

	return diffs
}

func schemaEqual(a, b map[string]interface{}) bool {
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	return string(aj) == string(bj)
}

func hashSnapshot(snap *ServerSnapshot) string {
	data, _ := json.Marshal(snap)
	return fmt.Sprintf("%x", simpleHash(data))
}

func simpleHash(data []byte) uint64 {
	var h uint64 = 14695981039346656037
	for _, b := range data {
		h ^= uint64(b)
		h *= 1099511628211
	}
	return h
}

func formatDiff(diff Diff) string {
	parts := []string{fmt.Sprintf("[%s] %s", diff.Severity, diff.Type)}
	if diff.Tool != "" {
		parts = append(parts, diff.Tool)
	}
	parts = append(parts, diff.Detail)
	return strings.Join(parts, ": ")
}
