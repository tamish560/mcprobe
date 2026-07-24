package main

import (
	"encoding/json"
	"testing"
)

func TestRenderSARIF_Empty(t *testing.T) {
	result := &ScanResult{}
	out, err := RenderSARIF(result)
	if err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var report SARIFReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(report.Runs) != 1 {
		t.Errorf("expected 1 run, got %d", len(report.Runs))
	}
	if report.Runs[0].Tool.Driver.Name != "mcprobe" {
		t.Errorf("expected mcprobe, got %s", report.Runs[0].Tool.Driver.Name)
	}
}

func TestRenderSARIF_WithFindings(t *testing.T) {
	result := &ScanResult{
		Findings: []Finding{
			{Title: "Injection", Detail: "prompt injection detected", Severity: "HIGH", ToolName: "tool1"},
		},
	}
	out, err := RenderSARIF(result)
	if err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var report SARIFReport
	json.Unmarshal([]byte(out), &report)
	if len(report.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(report.Runs[0].Results))
	}
	r := report.Runs[0].Results[0]
	if r.Level != "error" {
		t.Errorf("expected error level, got %s", r.Level)
	}
	if r.Message.Text == "" {
		t.Error("expected non-empty message")
	}
	if len(r.Locations) != 1 {
		t.Errorf("expected 1 location, got %d", len(r.Locations))
	}
}

func TestRenderSARIF_WithShadows(t *testing.T) {
	result := &ScanResult{
		Shadows: []ShadowConflict{
			{ToolName: "read", Severity: "HIGH", Detail: "conflict"},
		},
	}
	out, err := RenderSARIF(result)
	if err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var report SARIFReport
	json.Unmarshal([]byte(out), &report)
	if len(report.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(report.Runs[0].Results))
	}
	if report.Runs[0].Results[0].Level != "error" {
		t.Errorf("expected error for HIGH, got %s", report.Runs[0].Results[0].Level)
	}
}

func TestRenderSARIF_ShadowMediumLevel(t *testing.T) {
	result := &ScanResult{
		Shadows: []ShadowConflict{
			{ToolName: "read", Severity: "MEDIUM", Detail: "conflict"},
		},
	}
	out, _ := RenderSARIF(result)
	var report SARIFReport
	json.Unmarshal([]byte(out), &report)
	if report.Runs[0].Results[0].Level != "warning" {
		t.Errorf("expected warning for MEDIUM, got %s", report.Runs[0].Results[0].Level)
	}
}

func TestRenderJSON(t *testing.T) {
	result := &ScanResult{
		Server:    ServerInfo{Name: "test", Version: "1.0"},
		ToolCount: 3,
		RiskLevel: "LOW",
	}
	out, err := RenderJSON(result)
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if out == "" {
		t.Error("expected non-empty JSON")
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if m["riskLevel"] != "LOW" {
		t.Errorf("expected LOW, got %v", m["riskLevel"])
	}
}

func TestRenderSARIF_SchemaVersion(t *testing.T) {
	out, _ := RenderSARIF(&ScanResult{})
	var report SARIFReport
	json.Unmarshal([]byte(out), &report)
	if report.Version != "2.1.0" {
		t.Errorf("expected 2.1.0, got %s", report.Version)
	}
	if report.Schema == "" {
		t.Error("expected non-empty schema")
	}
}
