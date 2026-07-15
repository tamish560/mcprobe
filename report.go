package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

type SARIFReport struct {
	Schema   string           `json:"$schema"`
	Version  string           `json:"version"`
	Runs     []SARIFRun       `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool    `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string           `json:"name"`
	Version        string           `json:"version"`
	InformationURI string           `json:"informationUri"`
	Rules          []SARIFRule      `json:"rules"`
}

type SARIFRule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
}

type SARIFResult struct {
	RuleID    string         `json:"ruleId"`
	Level     string         `json:"level"`
	Message   struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
	} `json:"physicalLocation"`
}

func RenderText(result *ScanResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("mcprobe scan report\n"))
	sb.WriteString(fmt.Sprintf("========================================\n\n"))
	sb.WriteString(fmt.Sprintf("Server: %s v%s\n", result.Server.Name, result.Server.Version))
	sb.WriteString(fmt.Sprintf("Tools: %d  Prompts: %d  Resources: %d\n", len(result.Tools), len(result.Prompts), len(result.Resources)))
	sb.WriteString(fmt.Sprintf("Risk Score: %.0f/100  Level: %s\n\n", result.RiskScore, result.RiskLevel))

	if len(result.Findings) == 0 && len(result.Shadows) == 0 {
		sb.WriteString("No findings. Server looks clean.\n")
		return sb.String()
	}

	if len(result.Findings) > 0 {
		sb.WriteString(fmt.Sprintf("Findings (%d)\n", len(result.Findings)))
		sb.WriteString("----------------------------------------\n")
		for i, f := range result.Findings {
			sb.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, f.Severity, f.Title))
			if f.ToolName != "" {
				sb.WriteString(fmt.Sprintf("   Tool: %s\n", f.ToolName))
			}
			sb.WriteString(fmt.Sprintf("   %s\n", f.Detail))
			if f.Evidence != "" {
				sb.WriteString(fmt.Sprintf("   Pattern: %s\n", f.Evidence))
			}
			if f.Suggestion != "" {
				sb.WriteString(fmt.Sprintf("   Fix: %s\n", f.Suggestion))
			}
			sb.WriteString("\n")
		}
	}

	if len(result.Shadows) > 0 {
		sb.WriteString(fmt.Sprintf("Tool Shadowing (%d)\n", len(result.Shadows)))
		sb.WriteString("----------------------------------------\n")
		for _, s := range result.Shadows {
			sb.WriteString(fmt.Sprintf("[%s] %s\n", s.Severity, s.ToolName))
			sb.WriteString(fmt.Sprintf("   Servers: %s\n", strings.Join(s.Servers, ", ")))
			sb.WriteString(fmt.Sprintf("   %s\n\n", s.Detail))
		}
	}

	return sb.String()
}

func RenderJSON(result *ScanResult) (string, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func RenderSARIF(result *ScanResult) (string, error) {
	rulesMap := make(map[string]bool)
	var rules []SARIFRule
	var results []SARIFResult

	for _, f := range result.Findings {
		ruleID := f.Category
		if !rulesMap[ruleID] {
			rulesMap[ruleID] = true
			rule := SARIFRule{
				ID:   ruleID,
				Name: f.Category,
			}
			rule.ShortDescription.Text = f.Title
			rules = append(rules, rule)
		}

		level := "warning"
		switch f.Severity {
		case "CRITICAL", "HIGH":
			level = "error"
		case "MEDIUM":
			level = "warning"
		default:
			level = "note"
		}

		r := SARIFResult{
			RuleID: ruleID,
			Level:  level,
		}
		r.Message.Text = fmt.Sprintf("%s: %s", f.Title, f.Detail)
		if f.ToolName != "" {
			loc := SARIFLocation{}
			loc.PhysicalLocation.ArtifactLocation.URI = fmt.Sprintf("tool://%s", f.ToolName)
			r.Locations = append(r.Locations, loc)
		}
		results = append(results, r)
	}

	for _, s := range result.Shadows {
		ruleID := "tool-shadowing"
		if !rulesMap[ruleID] {
			rulesMap[ruleID] = true
			rule := SARIFRule{
				ID:   ruleID,
				Name: "tool-shadowing",
			}
			rule.ShortDescription.Text = "Tool name conflict across servers"
			rules = append(rules, rule)
		}

		level := "error"
		if s.Severity == "MEDIUM" {
			level = "warning"
		}
		r := SARIFResult{
			RuleID: ruleID,
			Level:  level,
		}
		r.Message.Text = s.Detail
		results = append(results, r)
	}

	report := SARIFReport{
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "mcprobe",
						Version:        "0.1.0",
						InformationURI: "https://github.com/tamish560/mcprobe",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
