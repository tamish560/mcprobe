package main

import (
	"flag"
	"os"
	"testing"
)

func resetFlags() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
}

func TestParseArgs_Defaults(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"mcprobe"}
	cfg, err := parseArgs()
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if cfg.Format != "text" {
		t.Errorf("expected text, got %s", cfg.Format)
	}
	if cfg.Timeout != 30 {
		t.Errorf("expected 30, got %d", cfg.Timeout)
	}
}

func TestParseArgs_Command(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"mcprobe", "-command", "node server.js"}
	cfg, err := parseArgs()
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if cfg.Command != "node server.js" {
		t.Errorf("expected 'node server.js', got %s", cfg.Command)
	}
}

func TestParseArgs_HTTP(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"mcprobe", "-http", "http://localhost:3000/mcp"}
	cfg, _ := parseArgs()
	if cfg.Endpoint != "http://localhost:3000/mcp" {
		t.Errorf("expected http://localhost:3000/mcp, got %s", cfg.Endpoint)
	}
}

func TestParseArgs_Format(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"mcprobe", "-format", "sarif"}
	cfg, _ := parseArgs()
	if cfg.Format != "sarif" {
		t.Errorf("expected sarif, got %s", cfg.Format)
	}
}

func TestParseArgs_Shadow(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"mcprobe", "-shadow", "-shadow-dir", "./baselines/"}
	cfg, _ := parseArgs()
	if !cfg.Shadow {
		t.Error("expected true")
	}
	if cfg.ShadowDir != "./baselines/" {
		t.Errorf("expected ./baselines/, got %s", cfg.ShadowDir)
	}
}

func TestParseArgs_ListOnly(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"mcprobe", "-list"}
	cfg, _ := parseArgs()
	if !cfg.ListOnly {
		t.Error("expected true")
	}
}

func TestParseArgs_Baseline(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"mcprobe", "-baseline", "snap.json"}
	cfg, _ := parseArgs()
	if cfg.Baseline != "snap.json" {
		t.Errorf("expected snap.json, got %s", cfg.Baseline)
	}
}

func TestParseArgs_Diff(t *testing.T) {
	resetFlags()
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"mcprobe", "-diff", "snap.json"}
	cfg, _ := parseArgs()
	if cfg.Diff != "snap.json" {
		t.Errorf("expected snap.json, got %s", cfg.Diff)
	}
}

func TestVersion(t *testing.T) {
	if version == "" {
		t.Error("expected non-empty version")
	}
}
