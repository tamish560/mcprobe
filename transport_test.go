package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPTransport_Send(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		var msg map[string]interface{}
		json.NewDecoder(r.Body).Decode(&msg)
		if msg["method"] != "initialize" {
			t.Errorf("expected initialize, got %v", msg["method"])
		}
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      msg["id"],
			"result":  map[string]interface{}{"ok": true},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	tr := NewHTTPTransport(srv.URL)
	resp, err := tr.Send(context.Background(), map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "initialize",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if resp["result"] == nil {
		t.Error("expected result")
	}
}

func TestHTTPTransport_SendNotification(t *testing.T) {
	got := make(chan map[string]interface{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg map[string]interface{}
		json.NewDecoder(r.Body).Decode(&msg)
		got <- msg
		w.WriteHeader(200)
	}))
	defer srv.Close()

	tr := NewHTTPTransport(srv.URL)
	tr.SendNotification(context.Background(), map[string]interface{}{
		"method": "notifications/initialized",
	})
	msg := <-got
	if msg["method"] != "notifications/initialized" {
		t.Errorf("expected notification, got %v", msg["method"])
	}
	if msg["jsonrpc"] != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %v", msg["jsonrpc"])
	}
}

func TestHTTPTransport_Close(t *testing.T) {
	tr := NewHTTPTransport("http://localhost:0")
	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestHTTPTransport_IDIncrements(t *testing.T) {
	var ids []float64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg map[string]interface{}
		json.NewDecoder(r.Body).Decode(&msg)
		ids = append(ids, msg["id"].(float64))
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      msg["id"],
			"result":  map[string]interface{}{},
		})
	}))
	defer srv.Close()

	tr := NewHTTPTransport(srv.URL)
	tr.Send(context.Background(), map[string]interface{}{"method": "a"})
	tr.Send(context.Background(), map[string]interface{}{"method": "b"})
	if len(ids) != 2 {
		t.Fatalf("expected 2, got %d", len(ids))
	}
	if ids[1] != ids[0]+1 {
		t.Errorf("expected incrementing IDs: %v", ids)
	}
}
