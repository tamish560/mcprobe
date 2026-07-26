package main

import (
	"encoding/json"
	"strings"
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

func TestRenderText_NoShadow(t *testing.T) {
	result := &ScanResult{
		Server:    ServerInfo{Name: "test-server", Version: "1.0"},
		Tools:     []Tool{{Name: "read", Description: "reads files"}},
		RiskScore: 10,
		RiskLevel: "LOW",
	}
	out := RenderText(result)
	if !strings.Contains(out, "test-server") {
		t.Fatalf("expected server name in output, got: %s", out)
	}
	if !strings.Contains(out, "tools: 1") {
		t.Fatalf("expected tool count in output, got: %s", out)
	}
	if !strings.Contains(out, "clean") {
		t.Fatalf("expected 'clean' message for no findings, got: %s", out)
	}
}

func TestRenderText_WithShadow(t *testing.T) {
	result := &ScanResult{
		Server: ServerInfo{Name: "test-server", Version: "1.0"},
		Tools:  []Tool{{Name: "read"}, {Name: "write"}},
		Shadows: []ShadowConflict{
			{ToolName: "read_file", Severity: "HIGH", Detail: "reads outside allowed paths", Servers: []string{"srv1", "srv2"}},
		},
		RiskScore: 50,
		RiskLevel: "MEDIUM",
	}
	out := RenderText(result)
	if !strings.Contains(out, "shadowing") || !strings.Contains(out, "read_file") {
		t.Fatalf("expected shadow tool name in output, got: %s", out)
	}
	if !strings.Contains(out, "srv1") {
		t.Fatalf("expected server name in shadow output, got: %s", out)
	}
}

func TestRenderText_WithFindings(t *testing.T) {
	result := &ScanResult{
		Server: ServerInfo{Name: "test-server", Version: "2.0"},
		Findings: []Finding{
			{Title: "Injection", Detail: "prompt injection", Severity: "HIGH", ToolName: "exec", Evidence: "ignore previous", Suggestion: "sanitize input"},
		},
		RiskScore: 80,
		RiskLevel: "HIGH",
	}
	out := RenderText(result)
	if !strings.Contains(out, "1 problems") {
		t.Fatalf("expected '1 problems', got: %s", out)
	}
	if !strings.Contains(out, "Injection") {
		t.Fatalf("expected finding title, got: %s", out)
	}
	if !strings.Contains(out, "exec") {
		t.Fatalf("expected tool name, got: %s", out)
	}
	if !strings.Contains(out, "sanitize input") {
		t.Fatalf("expected suggestion, got: %s", out)
	}
}

func TestRenderText_Empty(t *testing.T) {
	result := &ScanResult{
		Server: ServerInfo{Name: "empty-server", Version: "0.1"},
	}
	out := RenderText(result)
	if !strings.Contains(out, "empty-server") {
		t.Fatalf("expected server name, got: %s", out)
	}
	if !strings.Contains(out, "tools: 0") {
		t.Fatalf("expected 0 tools, got: %s", out)
	}
}
