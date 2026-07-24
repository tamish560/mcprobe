package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

type SSETransport struct {
	endpoint     string
	client       *http.Client
	postEndpoint string
	nextID       int
	mu           sync.Mutex
	reader       io.ReadCloser
	readerDone   chan struct{}
	pending      map[int]chan map[string]interface{}
}

func NewSSETransport(endpoint string) (*SSETransport, error) {
	t := &SSETransport{
		endpoint:   endpoint,
		client:     &http.Client{},
		pending:    make(map[int]chan map[string]interface{}),
		readerDone: make(chan struct{}),
	}

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("sse connect: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sse request: %w", err)
	}

	t.reader = resp.Body
	go t.readLoop()

	return t, nil
}

func (t *SSETransport) readLoop() {
	scanner := bufio.NewScanner(t.reader)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	var event, data string

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "event: ") {
			event = strings.TrimPrefix(line, "event: ")
		} else if strings.HasPrefix(line, "data: ") {
			data = strings.TrimPrefix(line, "data: ")
		} else if line == "" && data != "" {
			switch event {
			case "endpoint":
				t.postEndpoint = data
			case "message":
				var msg map[string]interface{}
				if err := json.Unmarshal([]byte(data), &msg); err == nil {
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
			}
			event = ""
			data = ""
		}
	}
	close(t.readerDone)
}

func (t *SSETransport) Send(ctx context.Context, msg map[string]interface{}) (map[string]interface{}, error) {
	if t.postEndpoint == "" {
		return nil, fmt.Errorf("sse: no post endpoint received yet")
	}

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

	req, err := http.NewRequestWithContext(ctx, "POST", t.postEndpoint, strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do: %w", err)
	}
	resp.Body.Close()

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

func (t *SSETransport) SendNotification(ctx context.Context, msg map[string]interface{}) {
	if t.postEndpoint == "" {
		return
	}
	msg["jsonrpc"] = "2.0"
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, "POST", t.postEndpoint, strings.NewReader(string(data)))
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

func (t *SSETransport) Close() error {
	if t.reader != nil {
		t.reader.Close()
	}
	return nil
}
