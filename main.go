package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

var version = "0.1.0"

type Config struct {
	Command    string
	Args       []string
	Endpoint   string
	SSEEndpoint string
	Format     string
	Baseline   string
	Diff       string
	Shadow     bool
	ShadowDir  string
	Timeout    int
	ListOnly   bool
	Output     string
}

func parseArgs() (*Config, error) {
	cfg := &Config{}

	flag.StringVar(&cfg.Command, "command", "", "command to run MCP server via stdio")
	flag.StringVar(&cfg.Endpoint, "http", "", "HTTP endpoint of MCP server")
	flag.StringVar(&cfg.SSEEndpoint, "sse", "", "SSE endpoint of MCP server")
	flag.StringVar(&cfg.Format, "format", "text", "output format: text, json, sarif")
	flag.StringVar(&cfg.Baseline, "baseline", "", "save baseline snapshot to file")
	flag.StringVar(&cfg.Diff, "diff", "", "compare current server against baseline file")
	flag.BoolVar(&cfg.Shadow, "shadow", false, "scan multiple servers for tool shadowing")
	flag.StringVar(&cfg.ShadowDir, "shadow-dir", "", "directory of baseline files to check for shadowing")
	flag.IntVar(&cfg.Timeout, "timeout", 30, "timeout in seconds")
	flag.BoolVar(&cfg.ListOnly, "list", false, "only list tools/prompts/resources, skip security scan")
	flag.StringVar(&cfg.Output, "out", "", "write output to file instead of stdout")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "mcprobe v%s\n\n", version)
		fmt.Fprintf(os.Stderr, "usage:\n")
		fmt.Fprintln(os.Stderr, "  mcprobe -command 'node server.js'")
		fmt.Fprintln(os.Stderr, "  mcprobe -http http://localhost:3000/mcp")
		fmt.Fprintln(os.Stderr, "  mcprobe -sse http://localhost:3000/sse")
		fmt.Fprintln(os.Stderr, "  mcprobe -command 'node server.js' -baseline snap.json")
		fmt.Fprintln(os.Stderr, "  mcprobe -command 'node server.js' -diff snap.json")
		fmt.Fprintln(os.Stderr, "  mcprobe -shadow -shadow-dir ./baselines/")
		fmt.Fprintln(os.Stderr, "  mcprobe -command 'node server.js' -format sarif")
		fmt.Fprintf(os.Stderr, "\nflags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()
	return cfg, nil
}

func main() {
	cfg, err := parseArgs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	if cfg.Command == "" && cfg.Endpoint == "" && cfg.SSEEndpoint == "" && !cfg.Shadow {
		flag.Usage()
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeout)*time.Second)
	defer cancel()

	if cfg.Shadow {
		runShadowCheck(ctx, cfg)
		return
	}

	if cfg.Command != "" {
		parts := strings.Fields(cfg.Command)
		if len(parts) == 0 {
			fmt.Fprintf(os.Stderr, "empty command. you gave me nothing to run.\n")
			os.Exit(1)
		}
		snap, err := scanStdio(ctx, parts[0], parts[1:], cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		outputResult(snap, cfg)
		return
	}

	if cfg.Endpoint != "" {
		snap, err := scanHTTP(ctx, cfg.Endpoint, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		outputResult(snap, cfg)
		return
	}

	if cfg.SSEEndpoint != "" {
		snap, err := scanSSE(ctx, cfg.SSEEndpoint, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		outputResult(snap, cfg)
		return
	}
}

func scanStdio(ctx context.Context, command string, args []string, cfg *Config) (*ScanResult, error) {
	transport, err := NewStdioTransport(ctx, command, args...)
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}
	defer transport.Close()

	client := NewClient(transport)
	snap, err := client.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}

	return processSnapshot(snap, cfg)
}

func scanHTTP(ctx context.Context, endpoint string, cfg *Config) (*ScanResult, error) {
	transport := NewHTTPTransport(endpoint)
	defer transport.Close()

	client := NewClient(transport)
	snap, err := client.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}

	return processSnapshot(snap, cfg)
}

func scanSSE(ctx context.Context, endpoint string, cfg *Config) (*ScanResult, error) {
	transport, err := NewSSETransport(endpoint)
	if err != nil {
		return nil, fmt.Errorf("sse transport: %w", err)
	}
	defer transport.Close()

	client := NewClient(transport)
	snap, err := client.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}

	return processSnapshot(snap, cfg)
}

func processSnapshot(snap *ServerSnapshot, cfg *Config) (*ScanResult, error) {
	if cfg.Baseline != "" {
		if err := SaveBaseline(snap, cfg.Baseline); err != nil {
			return nil, fmt.Errorf("save baseline: %w", err)
		}
		fmt.Fprintf(os.Stderr, "baseline saved to %s. come back when something changes.\n", cfg.Baseline)
	}

	if cfg.Diff != "" {
		old, err := LoadBaseline(cfg.Diff)
		if err != nil {
			return nil, fmt.Errorf("load baseline: %w", err)
		}
		diffs := DiffSnapshots(&old.Snapshot, snap)
		if len(diffs) > 0 {
			fmt.Fprintf(os.Stderr, "drift detected. %d changes since your last baseline.\n", len(diffs))
			fmt.Fprintf(os.Stderr, "someone updated the server. or someone replaced it.\n")
			fmt.Fprintf(os.Stderr, "either way, you trusted the old version. do you trust the new one?\n\n")
			for _, d := range diffs {
				fmt.Fprintf(os.Stderr, "  %s\n", formatDiff(d))
			}
		} else {
			fmt.Fprintf(os.Stderr, "no drift. server matches baseline. for now.\n")
		}
	}

	if cfg.ListOnly {
		return &ScanResult{
			Server:    snap.Info,
			Tools:     snap.Tools,
			Prompts:   snap.Prompts,
			Resources: snap.Resources,
			ToolCount: len(snap.Tools),
		}, nil
	}

	return ScanSnapshot(snap), nil
}

func runShadowCheck(ctx context.Context, cfg *Config) {
	if cfg.ShadowDir == "" {
		fmt.Fprintf(os.Stderr, "-shadow needs -shadow-dir. you forgot the directory.\n")
		os.Exit(1)
	}

	entries, err := os.ReadDir(cfg.ShadowDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "can't read that directory: %v\n", err)
		os.Exit(1)
	}

	snapshots := make(map[string]*ServerSnapshot)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := fmt.Sprintf("%s/%s", cfg.ShadowDir, entry.Name())
		baseline, err := LoadBaseline(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", entry.Name(), err)
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		snapshots[name] = &baseline.Snapshot
	}

	if len(snapshots) < 2 {
		fmt.Fprintf(os.Stderr, "need at least 2 baseline files. found %d. shadowing needs more than one server.\n", len(snapshots))
		os.Exit(1)
	}

	conflicts := DetectShadowing(snapshots)
	if len(conflicts) == 0 {
		fmt.Printf("no shadowing across %d servers. this time.\n", len(snapshots))
		return
	}

	fmt.Printf("shadowing detected. %d conflicts.\n", len(conflicts))
	fmt.Println("========================================")
	for _, c := range conflicts {
		fmt.Printf("[%s] %s\n", c.Severity, c.ToolName)
		fmt.Printf("   servers: %s\n", strings.Join(c.Servers, ", "))
		fmt.Printf("   %s\n\n", c.Detail)
	}
}

func outputResult(result *ScanResult, cfg *Config) {
	var output string
	var err error

	switch cfg.Format {
	case "json":
		output, err = RenderJSON(result)
	case "sarif":
		output, err = RenderSARIF(result)
	default:
		output = RenderText(result)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "rendering failed: %v\n", err)
		os.Exit(1)
	}

	if cfg.Output != "" {
		if err := os.WriteFile(cfg.Output, []byte(output), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "can't write that file: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "report written to %s\n", cfg.Output)
	} else {
		fmt.Println(output)
	}

	if result.RiskLevel == "CRITICAL" || result.RiskLevel == "HIGH" {
		os.Exit(2)
	}
}

func init() {
	_ = json.Marshal
}
