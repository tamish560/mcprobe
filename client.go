package main

import (
	"context"
	"encoding/json"
	"fmt"
)

type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

type Prompt struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Arguments   []map[string]interface{} `json:"arguments"`
}

type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MimeType    string `json:"mimeType"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ServerCapabilities struct {
	Tools     bool `json:"tools"`
	Prompts   bool `json:"prompts"`
	Resources bool `json:"resources"`
}

type ServerSnapshot struct {
	Info     ServerInfo        `json:"serverInfo"`
	Caps     ServerCapabilities `json:"capabilities"`
	Tools    []Tool            `json:"tools"`
	Prompts []Prompt          `json:"prompts"`
	Resources []Resource      `json:"resources"`
}

type Client struct {
	transport Transport
}

func NewClient(transport Transport) *Client {
	return &Client{transport: transport}
}

func (c *Client) Initialize(ctx context.Context) (ServerInfo, ServerCapabilities, error) {
	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "mcprobe",
				"version": "0.1.0",
			},
		},
	}

	resp, err := c.transport.Send(ctx, msg)
	if err != nil {
		return ServerInfo{}, ServerCapabilities{}, fmt.Errorf("initialize: %w", err)
	}

	if errVal, ok := resp["error"]; ok {
		return ServerInfo{}, ServerCapabilities{}, fmt.Errorf("server error: %v", errVal)
	}

	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		return ServerInfo{}, ServerCapabilities{}, fmt.Errorf("invalid response")
	}

	info := ServerInfo{}
	if serverInfo, ok := result["serverInfo"].(map[string]interface{}); ok {
		if v, ok := serverInfo["name"].(string); ok {
			info.Name = v
		}
		if v, ok := serverInfo["version"].(string); ok {
			info.Version = v
		}
	}

	caps := ServerCapabilities{}
	if capInfo, ok := result["capabilities"].(map[string]interface{}); ok {
		_, caps.Tools = capInfo["tools"]
		_, caps.Prompts = capInfo["prompts"]
		_, caps.Resources = capInfo["resources"]
	}

	c.sendNotification(ctx, "notifications/initialized")

	return info, caps, nil
}

func (c *Client) ListTools(ctx context.Context) ([]Tool, error) {
	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	}

	resp, err := c.transport.Send(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("list tools: %w", err)
	}

	if errVal, ok := resp["error"]; ok {
		return nil, fmt.Errorf("server error: %v", errVal)
	}

	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response")
	}

	toolsRaw, ok := result["tools"].([]interface{})
	if !ok {
		return nil, nil
	}

	var tools []Tool
	for _, t := range toolsRaw {
		tm, ok := t.(map[string]interface{})
		if !ok {
			continue
		}
		tool := Tool{}
		if v, ok := tm["name"].(string); ok {
			tool.Name = v
		}
		if v, ok := tm["description"].(string); ok {
			tool.Description = v
		}
		if v, ok := tm["inputSchema"].(map[string]interface{}); ok {
			tool.InputSchema = v
		}
		tools = append(tools, tool)
	}
	return tools, nil
}

func (c *Client) ListPrompts(ctx context.Context) ([]Prompt, error) {
	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "prompts/list",
		"params":  map[string]interface{}{},
	}

	resp, err := c.transport.Send(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("list prompts: %w", err)
	}

	if errVal, ok := resp["error"]; ok {
		return nil, fmt.Errorf("server error: %v", errVal)
	}

	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		return nil, nil
	}

	promptsRaw, ok := result["prompts"].([]interface{})
	if !ok {
		return nil, nil
	}

	var prompts []Prompt
	for _, p := range promptsRaw {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		prompt := Prompt{}
		if v, ok := pm["name"].(string); ok {
			prompt.Name = v
		}
		if v, ok := pm["description"].(string); ok {
			prompt.Description = v
		}
		if args, ok := pm["arguments"].([]interface{}); ok {
			for _, a := range args {
				if am, ok := a.(map[string]interface{}); ok {
					prompt.Arguments = append(prompt.Arguments, am)
				}
			}
		}
		prompts = append(prompts, prompt)
	}
	return prompts, nil
}

func (c *Client) ListResources(ctx context.Context) ([]Resource, error) {
	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "resources/list",
		"params":  map[string]interface{}{},
	}

	resp, err := c.transport.Send(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("list resources: %w", err)
	}

	if errVal, ok := resp["error"]; ok {
		return nil, fmt.Errorf("server error: %v", errVal)
	}

	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		return nil, nil
	}

	resourcesRaw, ok := result["resources"].([]interface{})
	if !ok {
		return nil, nil
	}

	var resources []Resource
	for _, r := range resourcesRaw {
		rm, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		res := Resource{}
		if v, ok := rm["uri"].(string); ok {
			res.URI = v
		}
		if v, ok := rm["name"].(string); ok {
			res.Name = v
		}
		if v, ok := rm["description"].(string); ok {
			res.Description = v
		}
		if v, ok := rm["mimeType"].(string); ok {
			res.MimeType = v
		}
		resources = append(resources, res)
	}
	return resources, nil
}

func (c *Client) Snapshot(ctx context.Context) (*ServerSnapshot, error) {
	info, caps, err := c.Initialize(ctx)
	if err != nil {
		return nil, err
	}

	snap := &ServerSnapshot{
		Info: info,
		Caps: caps,
	}

	if caps.Tools {
		tools, err := c.ListTools(ctx)
		if err != nil {
			return nil, fmt.Errorf("tools: %w", err)
		}
		snap.Tools = tools
	}

	if caps.Prompts {
		prompts, err := c.ListPrompts(ctx)
		if err != nil {
			return nil, fmt.Errorf("prompts: %w", err)
		}
		snap.Prompts = prompts
	}

	if caps.Resources {
		resources, err := c.ListResources(ctx)
		if err != nil {
			return nil, fmt.Errorf("resources: %w", err)
		}
		snap.Resources = resources
	}

	return snap, nil
}

func (c *Client) sendNotification(ctx context.Context, method string) {
	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
	}
	c.transport.SendNotification(ctx, msg)
}

func (c *Client) Close() error {
	return c.transport.Close()
}

func (s *ServerSnapshot) JSON() (string, error) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
