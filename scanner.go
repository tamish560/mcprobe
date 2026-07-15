package main

import (
	"fmt"
	"regexp"
	"strings"
)

type Finding struct {
	Severity   string `json:"severity"`
	Category   string `json:"category"`
	Title      string `json:"title"`
	Detail     string `json:"detail"`
	ToolName   string `json:"toolName,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	Suggestion string `json:"suggestion,omitempty"`
}

type ShadowConflict struct {
	ToolName  string `json:"toolName"`
	Servers   []string `json:"servers"`
	Severity  string `json:"severity"`
	Detail    string `json:"detail"`
}

type ScanResult struct {
	Server     ServerInfo        `json:"serverInfo"`
	Tools      []Tool            `json:"tools"`
	Prompts    []Prompt          `json:"prompts"`
	Resources  []Resource        `json:"resources"`
	Findings   []Finding         `json:"findings"`
	Shadows    []ShadowConflict  `json:"shadowConflicts"`
	RiskScore  float64           `json:"riskScore"`
	RiskLevel  string            `json:"riskLevel"`
	ToolCount  int               `json:"toolCount"`
}

var injectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore\s+(all\s+)?previous\s+instructions`),
	regexp.MustCompile(`(?i)disregard\s+(all\s+)?prior`),
	regexp.MustCompile(`(?i)you\s+are\s+now\s+(?:a|an)\s+\w+`),
	regexp.MustCompile(`(?i)act\s+as\s+(?:if|a|an)\s+`),
	regexp.MustCompile(`(?i)forget\s+(?:everything|all\s+prior)`),
	regexp.MustCompile(`(?i)system\s*:\s*you\s+are`),
	regexp.MustCompile(`(?i)pretend\s+(?:to\s+be|you\s+are)`),
	regexp.MustCompile(`(?i)(?:execute|run|eval)\s+(?:arbitrary\s+)?(?:command|code|script)`),
	regexp.MustCompile(`(?i)(?:read|access|fetch|send)\s+(?:any|all|every)\s+(?:file|env|secret|credential)`),
	regexp.MustCompile(`(?i)(?:rm\s+-rf|del\s+/?[sqa]?|format\s+disk|wipe\s+)`),
	regexp.MustCompile(`(?i)(?:curl|wget|fetch)\s+.*\|\s*(?:sh|bash|python|perl)`),
	regexp.MustCompile(`(?i)(?:exfiltrat|leak|upload|transmit)\s+(?:data|secrets|keys|tokens)`),
	regexp.MustCompile(`(?i)(?:disable|bypass|circumvent|deactivate)\s+(?:security|guard|filter|sandbox)`),
	regexp.MustCompile(`(?i)(?:grant|elevate|escalate)\s+(?:full|root|admin)\s+access`),
	regexp.MustCompile(`(?i)base64\s*decode|atob\s*\(`),
	regexp.MustCompile(`(?i)(?:sql\s+injection|drop\s+table|union\s+select)`),
	regexp.MustCompile(`(?i)(?:eval|exec|system)\s*\(\s*(?:input|user|request|payload|data)`),
	regexp.MustCompile(`(?i)(?:override|replace|intercept|hook)\s+(?:safety|policy|guardrail|alignment)`),
}

var suspiciousToolNamePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:read|write|exec|run|delete|remove|kill|stop|drop)\w*`),
	regexp.MustCompile(`(?i)(?:file|shell|system|process|env|secret|token|key)\w*`),
}

func ScanSnapshot(snap *ServerSnapshot) *ScanResult {
	result := &ScanResult{
		Server:    snap.Info,
		Tools:     snap.Tools,
		Prompts:   snap.Prompts,
		Resources: snap.Resources,
		ToolCount: len(snap.Tools),
	}

	for _, tool := range snap.Tools {
		scanToolDescription(&tool, result)
		scanToolSchema(&tool, result)
	}

	for _, prompt := range snap.Prompts {
		scanPrompt(&prompt, result)
	}

	for _, resource := range snap.Resources {
		scanResource(&resource, result)
	}

	result.RiskScore = calculateRiskScore(result)
	result.RiskLevel = riskLevel(result.RiskScore)

	return result
}

func scanToolDescription(tool *Tool, result *ScanResult) {
	if tool.Description == "" {
		result.Findings = append(result.Findings, Finding{
			Severity:   "LOW",
			Category:   "missing-metadata",
			Title:      "Tool has no description",
			Detail:     fmt.Sprintf("Tool '%s' has no description, making it impossible to audit its purpose", tool.Name),
			ToolName:   tool.Name,
			Suggestion: "Add a clear description to every tool",
		})
		return
	}

	for _, p := range injectionPatterns {
		if p.MatchString(tool.Description) {
			result.Findings = append(result.Findings, Finding{
				Severity:   "CRITICAL",
				Category:   "prompt-injection",
				Title:      "Tool description contains injection pattern",
				Detail:     fmt.Sprintf("Tool '%s' description contains a known prompt injection pattern", tool.Name),
				ToolName:   tool.Name,
				Evidence:   p.String(),
				Suggestion: "Remove instruction-like text from tool descriptions",
			})
		}
	}

	if len(tool.Description) > 2000 {
		result.Findings = append(result.Findings, Finding{
			Severity:   "MEDIUM",
			Category:   "oversized-description",
			Title:      "Tool description is unusually large",
			Detail:     fmt.Sprintf("Tool '%s' description is %d characters, which may hide embedded instructions", tool.Name, len(tool.Description)),
			ToolName:   tool.Name,
			Suggestion: "Keep tool descriptions concise and focused",
		})
	}
}

func scanToolSchema(tool *Tool, result *ScanResult) {
	if tool.InputSchema == nil {
		result.Findings = append(result.Findings, Finding{
			Severity:   "LOW",
			Category:   "missing-schema",
			Title:      "Tool has no input schema",
			Detail:     fmt.Sprintf("Tool '%s' has no input schema defined", tool.Name),
			ToolName:   tool.Name,
			Suggestion: "Define an input schema for type safety and validation",
		})
		return
	}

	if props, ok := tool.InputSchema["properties"].(map[string]interface{}); ok {
		for propName, propVal := range props {
			propMap, ok := propVal.(map[string]interface{})
			if !ok {
				continue
			}
			if desc, ok := propMap["description"].(string); ok {
				for _, p := range injectionPatterns {
					if p.MatchString(desc) {
						result.Findings = append(result.Findings, Finding{
							Severity:   "HIGH",
							Category:   "prompt-injection",
							Title:      "Schema property contains injection pattern",
							Detail:     fmt.Sprintf("Tool '%s' property '%s' description contains injection pattern", tool.Name, propName),
							ToolName:   tool.Name,
							Evidence:   p.String(),
							Suggestion: "Remove instruction-like text from schema descriptions",
						})
					}
				}
			}
		}
	}

	if req, ok := tool.InputSchema["required"].([]interface{}); ok && len(req) > 10 {
		result.Findings = append(result.Findings, Finding{
			Severity:   "LOW",
			Category:   "complex-schema",
			Title:      "Tool has many required fields",
			Detail:     fmt.Sprintf("Tool '%s' has %d required fields, increasing attack surface", tool.Name, len(req)),
			ToolName:   tool.Name,
		})
	}
}

func scanPrompt(prompt *Prompt, result *ScanResult) {
	if prompt.Description == "" {
		result.Findings = append(result.Findings, Finding{
			Severity: "LOW",
			Category: "missing-metadata",
			Title:    "Prompt has no description",
			Detail:   fmt.Sprintf("Prompt '%s' has no description", prompt.Name),
		})
		return
	}

	for _, p := range injectionPatterns {
		if p.MatchString(prompt.Description) {
			result.Findings = append(result.Findings, Finding{
				Severity: "HIGH",
				Category: "prompt-injection",
				Title:    "Prompt description contains injection pattern",
				Detail:   fmt.Sprintf("Prompt '%s' description contains a known prompt injection pattern", prompt.Name),
				Evidence: p.String(),
			})
		}
	}
}

func scanResource(resource *Resource, result *ScanResult) {
	if resource.URI == "" {
		result.Findings = append(result.Findings, Finding{
			Severity: "MEDIUM",
			Category: "invalid-resource",
			Title:    "Resource has no URI",
			Detail:   fmt.Sprintf("Resource '%s' has no URI", resource.Name),
		})
	}

	if strings.Contains(resource.URI, "..") {
		result.Findings = append(result.Findings, Finding{
			Severity: "HIGH",
			Category: "path-traversal",
			Title:    "Resource URI contains path traversal",
			Detail:   fmt.Sprintf("Resource '%s' URI '%s' contains '..' which may allow path traversal", resource.Name, resource.URI),
		})
	}
}

func DetectShadowing(snapshots map[string]*ServerSnapshot) []ShadowConflict {
	var conflicts []ShadowConflict
	toolOwners := make(map[string][]string)

	for serverName, snap := range snapshots {
		for _, tool := range snap.Tools {
			toolOwners[tool.Name] = append(toolOwners[tool.Name], serverName)
		}
	}

	for toolName, servers := range toolOwners {
		if len(servers) > 1 {
			severity := "HIGH"
			if len(servers) > 3 {
				severity = "CRITICAL"
			}
			conflicts = append(conflicts, ShadowConflict{
				ToolName: toolName,
				Servers:  servers,
				Severity: severity,
				Detail:   fmt.Sprintf("Tool '%s' is defined by %d servers: %s", toolName, len(servers), strings.Join(servers, ", ")),
			})
		}
	}

	return conflicts
}

func calculateRiskScore(result *ScanResult) float64 {
	score := 0.0
	for _, f := range result.Findings {
		switch f.Severity {
		case "CRITICAL":
			score += 25
		case "HIGH":
			score += 15
		case "MEDIUM":
			score += 7
		case "LOW":
			score += 2
		}
	}
	for _, s := range result.Shadows {
		if s.Severity == "CRITICAL" {
			score += 20
		} else {
			score += 10
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

func riskLevel(score float64) string {
	switch {
	case score >= 75:
		return "CRITICAL"
	case score >= 50:
		return "HIGH"
	case score >= 25:
		return "MEDIUM"
	case score >= 10:
		return "LOW"
	default:
		return "MINIMAL"
	}
}
