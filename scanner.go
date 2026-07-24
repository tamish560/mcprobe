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
	ToolName string   `json:"toolName"`
	Servers  []string `json:"servers"`
	Severity string   `json:"severity"`
	Detail   string   `json:"detail"`
}

type ScanResult struct {
	Server    ServerInfo       `json:"serverInfo"`
	Tools     []Tool           `json:"tools"`
	Prompts   []Prompt         `json:"prompts"`
	Resources []Resource       `json:"resources"`
	Findings  []Finding        `json:"findings"`
	Shadows   []ShadowConflict `json:"shadowConflicts"`
	RiskScore float64          `json:"riskScore"`
	RiskLevel string           `json:"riskLevel"`
	ToolCount int              `json:"toolCount"`
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
		scanResourceExposure(&tool, result)
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
			Title:      "no description",
			Detail:     fmt.Sprintf("tool '%s' has no description. the model will guess what it does. the model will guess wrong.", tool.Name),
			ToolName:   tool.Name,
			Suggestion: "write a description. it's not optional.",
		})
		return
	}

	for _, p := range injectionPatterns {
		if p.MatchString(tool.Description) {
			result.Findings = append(result.Findings, Finding{
				Severity:   "CRITICAL",
				Category:   "prompt-injection",
				Title:      "injection in tool description",
				Detail:     fmt.Sprintf("tool '%s' has injection text in its description. a model will follow it. this is not a warning. this is what will happen.", tool.Name),
				ToolName:   tool.Name,
				Evidence:   p.String(),
				Suggestion: "remove the instruction text. or don't. see what happens.",
			})
		}
	}

	if len(tool.Description) > 2000 {
		result.Findings = append(result.Findings, Finding{
			Severity:   "MEDIUM",
			Category:   "oversized-description",
			Title:      "description is too long",
			Detail:     fmt.Sprintf("tool '%s' description is %d characters. nobody reads that. including the model. something could be hiding in there.", tool.Name, len(tool.Description)),
			ToolName:   tool.Name,
			Suggestion: "cut it down. if you need 2000 chars to describe a tool, the tool does too much.",
		})
	}
}

func scanToolSchema(tool *Tool, result *ScanResult) {
	if tool.InputSchema == nil {
		result.Findings = append(result.Findings, Finding{
			Severity:   "LOW",
			Category:   "missing-schema",
			Title:      "no input schema",
			Detail:     fmt.Sprintf("tool '%s' has no schema. the model will send whatever it wants. you will receive whatever it sends.", tool.Name),
			ToolName:   tool.Name,
			Suggestion: "define a schema. or enjoy the chaos.",
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
							Title:      "injection in schema",
							Detail:     fmt.Sprintf("tool '%s' property '%s' has injection text. you put it in the schema. the model reads the schema. good luck.", tool.Name, propName),
							ToolName:   tool.Name,
							Evidence:   p.String(),
							Suggestion: "remove it.",
						})
					}
				}
			}
		}
	}

	if req, ok := tool.InputSchema["required"].([]interface{}); ok && len(req) > 10 {
		result.Findings = append(result.Findings, Finding{
			Severity: "LOW",
			Category: "complex-schema",
			Title:    "too many required fields",
			Detail:   fmt.Sprintf("tool '%s' has %d required fields. that's not a tool. that's a form.", tool.Name, len(req)),
			ToolName: tool.Name,
		})
	}
}

func scanPrompt(prompt *Prompt, result *ScanResult) {
	if prompt.Description == "" {
		result.Findings = append(result.Findings, Finding{
			Severity: "LOW",
			Category: "missing-metadata",
			Title:    "prompt has no description",
			Detail:   fmt.Sprintf("prompt '%s' has no description. nobody knows what it does. including you, probably.", prompt.Name),
		})
		return
	}

	for _, p := range injectionPatterns {
		if p.MatchString(prompt.Description) {
			result.Findings = append(result.Findings, Finding{
				Severity: "HIGH",
				Category: "prompt-injection",
				Title:    "injection in prompt",
				Detail:   fmt.Sprintf("prompt '%s' has injection text in its description. you put instructions in a prompt description. think about that.", prompt.Name),
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
			Title:    "resource has no URI",
			Detail:   fmt.Sprintf("resource '%s' has no URI. it points to nothing. it is nothing.", resource.Name),
		})
	}

	if strings.Contains(resource.URI, "..") {
		result.Findings = append(result.Findings, Finding{
			Severity: "HIGH",
			Category: "path-traversal",
			Title:    "path traversal in resource URI",
			Detail:   fmt.Sprintf("resource '%s' URI is '%s'. it has '..' in it. you know what that does. or you should.", resource.Name, resource.URI),
		})
	}
}

var sensitivePathPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)/(etc|root|var|proc|sys)(/|$)`),
	regexp.MustCompile(`(?i)/(home|Users)[^/]*/\.(ssh|gnupg|aws|config)`),
	regexp.MustCompile(`(?i)\.(env|pem|key|pfx|p12|keystore)`),
	regexp.MustCompile(`(?i)(password|secret|token|credential|apikey|api_key)`),
}

func scanResourceExposure(tool *Tool, result *ScanResult) {
	if tool.InputSchema == nil {
		return
	}

	props, ok := tool.InputSchema["properties"].(map[string]interface{})
	if !ok {
		return
	}

	for propName, propVal := range props {
		propMap, ok := propVal.(map[string]interface{})
		if !ok {
			continue
		}

		propType, _ := propMap["type"].(string)
		if propType != "string" {
			continue
		}

		desc, _ := propMap["description"].(string)
		combined := propName + " " + desc

		for _, p := range sensitivePathPatterns {
			if p.MatchString(combined) {
				result.Findings = append(result.Findings, Finding{
					Severity:   "HIGH",
					Category:   "resource-exposure",
					Title:      "tool wants your secrets",
					Detail:     fmt.Sprintf("tool '%s' parameter '%s' references sensitive files or credentials. /etc, .ssh, .env, keys. you connected this to your agent. think about that.", tool.Name, propName),
					ToolName:   tool.Name,
					Evidence:   p.String(),
					Suggestion: "restrict the parameter. or don't. it's your server.",
				})
			}
		}

		if strings.Contains(strings.ToLower(propName), "path") || strings.Contains(strings.ToLower(propName), "file") || strings.Contains(strings.ToLower(propName), "dir") {
			if desc == "" || strings.Contains(strings.ToLower(desc), "any") || strings.Contains(strings.ToLower(desc), "arbitrary") {
				result.Findings = append(result.Findings, Finding{
					Severity:   "MEDIUM",
					Category:   "resource-exposure",
					Title:      "unrestricted file access",
					Detail:     fmt.Sprintf("tool '%s' parameter '%s' takes any file path. /etc/passwd. your ssh keys. your .env. nothing stops it. but the README has a nice logo so it's probably fine.", tool.Name, propName),
					ToolName:   tool.Name,
					Suggestion: "add path validation. or keep pretending nothing will go wrong.",
				})
			}
		}
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
				Detail:   fmt.Sprintf("tool '%s' exists on %d servers: %s. your agent won't know which one it's calling. neither will you. this will be fun to debug.", toolName, len(servers), strings.Join(servers, ", ")),
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
