package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
)

type Transport interface {
	Send(ctx context.Context, msg map[string]interface{}) (map[string]interface{}, error)
	SendNotification(ctx context.Context, msg map[string]interface{})
	Close() error
}

type StdioTransport struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	mu     sync.Mutex
	nextID int
	pending map[int]chan map[string]interface{}
	readerDone chan struct{}
}

func NewStdioTransport(ctx context.Context, command string, args ...string) (*StdioTransport, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start process: %w", err)
	}
	t := &StdioTransport{
		cmd:      cmd,
		stdin:    stdin,
		stdout:   stdout,
		pending:  make(map[int]chan map[string]interface{}),
		readerDone: make(chan struct{}),
	}
	go t.readLoop()
	return t, nil
}

func (t *StdioTransport) readLoop() {
	scanner := bufio.NewScanner(t.stdout)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var msg map[string]interface{}
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}
		if idVal, ok := msg["id"]; ok {
			id := int(idVal.(float64))
			t.mu.Lock()
			ch, exists := t.pending[id]
			if exists {
				delete(t.pending, id)
			}
			t.mu.Unlock()
			if exists {
				ch <- msg
			}
		}
	}
	close(t.readerDone)
}

func (t *StdioTransport) Send(ctx context.Context, msg map[string]interface{}) (map[string]interface{}, error) {
	t.mu.Lock()
	id := t.nextID
	t.nextID++
	msg["id"] = id
	ch := make(chan map[string]interface{}, 1)
	t.pending[id] = ch
	t.mu.Unlock()

	data, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	data = append(data, '\n')

	_, err = t.stdin.Write(data)
	if err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	select {
	case resp := <-ch:
		return resp, nil
	case <-ctx.Done():
		t.mu.Lock()
		delete(t.pending, id)
		t.mu.Unlock()
		return nil, ctx.Err()
	}
}

func (t *StdioTransport) SendNotification(ctx context.Context, msg map[string]interface{}) {
	msg["jsonrpc"] = "2.0"
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	data = append(data, '\n')
	t.stdin.Write(data)
}

func (t *StdioTransport) Close() error {
	t.stdin.Close()
	t.cmd.Wait()
	return nil
}

type HTTPTransport struct {
	endpoint string
	client   *http.Client
	nextID   int
	mu       sync.Mutex
}

func NewHTTPTransport(endpoint string) *HTTPTransport {
	return &HTTPTransport{
		endpoint: endpoint,
		client:   &http.Client{},
	}
}

func (t *HTTPTransport) Send(ctx context.Context, msg map[string]interface{}) (map[string]interface{}, error) {
	t.mu.Lock()
	id := t.nextID
	t.nextID++
	t.mu.Unlock()
	msg["id"] = id

	data, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", t.endpoint, strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	return result, nil
}

func (t *HTTPTransport) SendNotification(ctx context.Context, msg map[string]interface{}) {
	msg["jsonrpc"] = "2.0"
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, "POST", t.endpoint, strings.NewReader(string(data)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

func (t *HTTPTransport) Close() error {
	return nil
}
