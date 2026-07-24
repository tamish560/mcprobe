package main

import (
	"context"
	"testing"
)

type mockTransport struct {
	responses []map[string]interface{}
	sent      []map[string]interface{}
	notifs    []map[string]interface{}
	closed    bool
	idx       int
}

func (m *mockTransport) Send(ctx context.Context, msg map[string]interface{}) (map[string]interface{}, error) {
	m.sent = append(m.sent, msg)
	if m.idx < len(m.responses) {
		r := m.responses[m.idx]
		m.idx++
		return r, nil
	}
	return map[string]interface{}{"error": "no more responses"}, nil
}

func (m *mockTransport) SendNotification(ctx context.Context, msg map[string]interface{}) {
	m.notifs = append(m.notifs, msg)
}

func (m *mockTransport) Close() error {
	m.closed = true
	return nil
}

func TestClient_Initialize(t *testing.T) {
	mt := &mockTransport{
		responses: []map[string]interface{}{
			{"result": map[string]interface{}{
				"serverInfo": map[string]interface{}{"name": "test-server", "version": "1.0"},
				"capabilities": map[string]interface{}{
					"tools":     map[string]interface{}{},
					"prompts":   map[string]interface{}{},
					"resources": map[string]interface{}{},
				},
			}},
		},
	}
	c := NewClient(mt)
	info, caps, err := c.Initialize(context.Background())
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if info.Name != "test-server" {
		t.Errorf("expected test-server, got %s", info.Name)
	}
	if info.Version != "1.0" {
		t.Errorf("expected 1.0, got %s", info.Version)
	}
	if !caps.Tools || !caps.Prompts || !caps.Resources {
		t.Error("expected all caps true")
	}
	if len(mt.notifs) != 1 {
		t.Errorf("expected 1 notification, got %d", len(mt.notifs))
	}
}

func TestClient_InitializeError(t *testing.T) {
	mt := &mockTransport{
		responses: []map[string]interface{}{
			{"error": "server rejected"},
		},
	}
	c := NewClient(mt)
	_, _, err := c.Initialize(context.Background())
	if err == nil {
		t.Error("expected error")
	}
}

func TestClient_InitializeInvalidResponse(t *testing.T) {
	mt := &mockTransport{
		responses: []map[string]interface{}{
			{"result": "not a map"},
		},
	}
	c := NewClient(mt)
	_, _, err := c.Initialize(context.Background())
	if err == nil {
		t.Error("expected error")
	}
}

func TestClient_ListTools(t *testing.T) {
	mt := &mockTransport{
		responses: []map[string]interface{}{
			{"result": map[string]interface{}{
				"tools": []interface{}{
					map[string]interface{}{"name": "read_file", "description": "reads a file"},
					map[string]interface{}{"name": "write_file", "description": "writes a file"},
				},
			}},
		},
	}
	c := NewClient(mt)
	tools, err := c.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}
	if tools[0].Name != "read_file" {
		t.Errorf("expected read_file, got %s", tools[0].Name)
	}
	if tools[0].Description != "reads a file" {
		t.Errorf("expected description, got %s", tools[0].Description)
	}
}

func TestClient_ListToolsEmpty(t *testing.T) {
	mt := &mockTransport{
		responses: []map[string]interface{}{
			{"result": map[string]interface{}{}},
		},
	}
	c := NewClient(mt)
	tools, err := c.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if tools != nil {
		t.Errorf("expected nil, got %v", tools)
	}
}

func TestClient_ListToolsError(t *testing.T) {
	mt := &mockTransport{
		responses: []map[string]interface{}{
			{"error": "denied"},
		},
	}
	c := NewClient(mt)
	_, err := c.ListTools(context.Background())
	if err == nil {
		t.Error("expected error")
	}
}

func TestClient_ListPrompts(t *testing.T) {
	mt := &mockTransport{
		responses: []map[string]interface{}{
			{"result": map[string]interface{}{
				"prompts": []interface{}{
					map[string]interface{}{"name": "summarize", "description": "summarize text"},
				},
			}},
		},
	}
	c := NewClient(mt)
	prompts, err := c.ListPrompts(context.Background())
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}
	if len(prompts) != 1 {
		t.Fatalf("expected 1, got %d", len(prompts))
	}
	if prompts[0].Name != "summarize" {
		t.Errorf("expected summarize, got %s", prompts[0].Name)
	}
}

func TestClient_ListPromptsEmpty(t *testing.T) {
	mt := &mockTransport{
		responses: []map[string]interface{}{
			{"result": "invalid"},
		},
	}
	c := NewClient(mt)
	prompts, err := c.ListPrompts(context.Background())
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}
	if prompts != nil {
		t.Errorf("expected nil, got %v", prompts)
	}
}

func TestClient_ListResources(t *testing.T) {
	mt := &mockTransport{
		responses: []map[string]interface{}{
			{"result": map[string]interface{}{
				"resources": []interface{}{
					map[string]interface{}{"uri": "file:///test", "name": "test", "description": "a test", "mimeType": "text/plain"},
				},
			}},
		},
	}
	c := NewClient(mt)
	resources, err := c.ListResources(context.Background())
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1, got %d", len(resources))
	}
	if resources[0].URI != "file:///test" {
		t.Errorf("expected file:///test, got %s", resources[0].URI)
	}
	if resources[0].MimeType != "text/plain" {
		t.Errorf("expected text/plain, got %s", resources[0].MimeType)
	}
}

func TestClient_Snapshot(t *testing.T) {
	mt := &mockTransport{
		responses: []map[string]interface{}{
			{"result": map[string]interface{}{
				"serverInfo": map[string]interface{}{"name": "srv", "version": "2.0"},
				"capabilities": map[string]interface{}{
					"tools":     map[string]interface{}{},
					"prompts":   map[string]interface{}{},
					"resources": map[string]interface{}{},
				},
			}},
			{"result": map[string]interface{}{
				"tools": []interface{}{
					map[string]interface{}{"name": "t1", "description": "tool 1"},
				},
			}},
			{"result": map[string]interface{}{
				"prompts": []interface{}{
					map[string]interface{}{"name": "p1", "description": "prompt 1"},
				},
			}},
			{"result": map[string]interface{}{
				"resources": []interface{}{
					map[string]interface{}{"uri": "r1", "name": "res1"},
				},
			}},
		},
	}
	c := NewClient(mt)
	snap, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.Info.Name != "srv" {
		t.Errorf("expected srv, got %s", snap.Info.Name)
	}
	if len(snap.Tools) != 1 {
		t.Errorf("expected 1 tool, got %d", len(snap.Tools))
	}
	if len(snap.Prompts) != 1 {
		t.Errorf("expected 1 prompt, got %d", len(snap.Prompts))
	}
	if len(snap.Resources) != 1 {
		t.Errorf("expected 1 resource, got %d", len(snap.Resources))
	}
}

func TestClient_SnapshotNoCaps(t *testing.T) {
	mt := &mockTransport{
		responses: []map[string]interface{}{
			{"result": map[string]interface{}{
				"serverInfo":   map[string]interface{}{"name": "srv", "version": "1"},
				"capabilities": map[string]interface{}{},
			}},
		},
	}
	c := NewClient(mt)
	snap, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snap.Tools) != 0 {
		t.Errorf("expected 0 tools, got %d", len(snap.Tools))
	}
}

func TestClient_Close(t *testing.T) {
	mt := &mockTransport{}
	c := NewClient(mt)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !mt.closed {
		t.Error("expected transport closed")
	}
}

func TestServerSnapshot_JSON(t *testing.T) {
	snap := &ServerSnapshot{
		Info:  ServerInfo{Name: "test", Version: "1.0"},
		Caps:  ServerCapabilities{Tools: true},
		Tools: []Tool{{Name: "t", Description: "d"}},
	}
	out, err := snap.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if out == "" {
		t.Error("expected non-empty JSON")
	}
}
