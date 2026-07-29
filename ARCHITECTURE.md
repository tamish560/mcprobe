# Architecture

## Overview

mcprobe is a security scanner for MCP servers. Point it at any MCP server (stdio, HTTP, or SSE), and it connects, enumerates all tools/prompts/resources, runs 18 injection-detection patterns against each, checks for tool shadowing across servers, and produces a risk-scored report in text, JSON, or SARIF format.

```
  +----------+     +----------+     +----------+
  | stdio    |     | HTTP     |     | SSE      |
  | transport|     | transport|     | transport|
  +----+-----+     +----+-----+     +----+-----+
       |                |                |
       +-------+--------+-------+--------+
               |               |
          +----v----+    +-----v-----+
          | client   |    |  scanner   |
          | (MCP)    |    | (18 regex  |
          +----+----+    |  patterns) |
               |         +-----+-----+
               v               |
          +----+----+    +-----v-----+
          | server  |--->| snapshot   |
          | (target)|    | (tools,    |
          +---------+    |  prompts,  |
                         |  resources)|
                         +-----+------+
                               |
                    +----------+----------+
                    |                     |
              +-----v------+        +-----v-----+
              | risk score |        | report     |
              | (0-100)    |        | (text/json |
              +------------+        |  /sarif)   |
                                    +-----------+
```

## Design Principles

1. **Transport-agnostic.** The scanner does not care how the server communicates. Stdio, HTTP, and SSE all implement the same `Transport` interface. The scanner works identically against all three.
2. **Connect, scan, disconnect.** mcprobe is a one-shot tool, not a proxy. It connects, enumerates, scans, reports, and exits. No long-running process, no state to maintain.
3. **Baseline diffing.** Save a snapshot of a known-good server state. Later, compare the current state against it. Detects tool removal, tool addition, description changes, and schema modifications.
4. **Tool shadowing detection.** When multiple MCP servers are composed, a malicious server can register a tool with the same name as a trusted server's tool. mcprobe detects these conflicts across baseline files.
5. **SARIF output.** Results can be emitted in SARIF v2.1.0 format for CI/CD integration (GitHub Code Scanning, Azure DevOps, etc.).

## Components

### transport (`transport.go`)

The `Transport` interface abstracts the communication channel:

```go
type Transport interface {
    Send(ctx, msg) (map[string]interface{}, error)
    SendNotification(ctx, msg)
    Close() error
}
```

Three implementations:

**StdioTransport:** Spawns the MCP server as a child process. Communicates over stdin/stdout with newline-delimited JSON-RPC. Uses a background reader goroutine to dispatch responses to pending request channels by JSON-RPC ID. Mutex-protected for concurrent send.

**HTTPTransport:** Sends JSON-RPC over HTTP POST. One request per connection. Simple, no state.

**SSETransport:** Connects to an SSE endpoint, receives server messages on the event stream, sends requests via HTTP POST to the server's message endpoint. Same pending-request pattern as stdio.

### client (`client.go`)

MCP client. Implements the JSON-RPC handshake:

1. `Initialize()` -- sends `initialize` with protocol version 2024-11-05, receives server info and capabilities.
2. `ListTools()` -- sends `notifications/initialized` then `tools/list`. Parses tool name, description, and input schema.
3. `ListPrompts()` -- sends `prompts/list`. Parses prompt name, description, and arguments.
4. `ListResources()` -- sends `resources/list`. Parses resource URI, name, description, and MIME type.

Returns a `ServerSnapshot` containing all server metadata.

### scanner (`scanner.go`)

The security analysis engine. 18 regex patterns covering:

| Category | Patterns | Severity |
|---|---|---|
| Prompt injection | "ignore previous instructions", "disregard prior", "you are now a...", "act as if", "pretend to be", "forget everything" | CRITICAL/HIGH |
| Code execution | "execute arbitrary command", "eval/system/popen with input" | CRITICAL |
| Data exfiltration | "exfiltrate/leak/upload/transmit data/secrets/keys", "curl|sh pipe" | CRITICAL |
| Destructive | "rm -rf", "format disk", "wipe" | CRITICAL |
| Security bypass | "disable/bypass/circumvent security/guard/filter/sandbox" | HIGH |
| Privilege escalation | "grant/elevate full/root/admin access" | HIGH |
| Obfuscation | "base64 decode", "atob()" | MEDIUM |
| SQL injection | "sql injection", "drop table", "union select" | HIGH |
| Safety override | "override/replace/intercept/hook safety/policy/guardrail" | HIGH |
| Resource exposure | "read/access/fetch/send any file/env/secret" | HIGH |
| Missing metadata | tool with no description | LOW |

**Scan targets:**
- Tool descriptions
- Tool input schemas (checks for overly permissive inputs)
- Prompt descriptions and arguments
- Resource descriptions and URIs

**Risk scoring:** Weighted sum of findings by severity, normalized to 0-100.
| Severity | Points |
|---|---|
| CRITICAL | 25 |
| HIGH | 15 |
| MEDIUM | 8 |
| LOW | 3 |

Risk levels: 0-20 LOW, 21-50 MEDIUM, 51-75 HIGH, 76-100 CRITICAL.

### baseline (`baseline.go`)

Snapshot persistence and diffing.

**Save:** `SaveBaseline(snapshot, path)` serializes the server snapshot to JSON with a timestamp and hash. Written to disk (0644).

**Load:** `LoadBaseline(path)` reads and parses a baseline file.

**Diff:** `DiffSnapshots(old, new)` compares two snapshots and returns a list of changes:
- `tool-removed` -- tool that existed before is gone (HIGH)
- `tool-added` -- new tool that was not in baseline (MEDIUM)
- `description-changed` -- tool description was modified (HIGH, could indicate injection)
- `schema-changed` -- tool input schema was modified (HIGH)
- `prompt-added` / `prompt-removed` -- prompt changes (MEDIUM)
- `resource-added` / `resource-removed` -- resource changes (LOW)

### Shadow detection (`scanner.go`)

Tool shadowing: when multiple MCP servers are composed into a single agent, a malicious server can register a tool with the same name as a trusted server's tool. The agent cannot distinguish which server handles the call.

`runShadowCheck(ctx, cfg)`:
1. Load all baseline files from `-shadow-dir`.
2. Build a map of tool name -> list of servers that expose it.
3. Any tool name that appears in more than one server is a `ShadowConflict`.
4. Report conflicts with severity based on whether descriptions match (same name, different description = higher risk).

### report (`report.go`)

Three output formats:

**Text:** Human-readable. Server info, tool/prompt/resource counts, risk score, findings with severity/category/detail/suggestion. Shadow conflicts listed separately.

**JSON:** Machine-readable. Full `ScanResult` struct serialized to JSON. Includes all findings, shadows, risk score, and metadata.

**SARIF:** Static Analysis Results Interchange Format v2.1.0. Compatible with GitHub Code Scanning, Azure DevOps, and any SARIF-consuming tool. Each finding becomes a SARIF result with rule ID, level, and message. Tool/prompt/resource URIs become artifact locations.

### Config

Command-line flags only. No config file, no env vars.

| Flag | Default | Purpose |
|---|---|---|
| `-command` | none | Command to run MCP server via stdio |
| `-http` | none | HTTP endpoint of MCP server |
| `-sse` | none | SSE endpoint of MCP server |
| `-format` | text | Output format: text, json, sarif |
| `-baseline` | none | Save baseline snapshot to file |
| `-diff` | none | Compare current server against baseline file |
| `-shadow` | false | Scan multiple servers for tool shadowing |
| `-shadow-dir` | none | Directory of baseline files for shadow check |
| `-timeout` | 30 | Timeout in seconds |
| `-list` | false | Only list tools/prompts/resources, skip security scan |
| `-out` | none | Write output to file instead of stdout |

## Process Model

Single-shot CLI. Connect, scan, report, exit. No daemon, no server, no state between runs. Timeout-enforced via `context.WithTimeout`.

## Testing

100 tests, 58.6% coverage. Tests cover:
- Scanner: all 18 patterns, risk scoring, risk levels, all scan targets
- Baseline: save, load, diff (tool added/removed/changed, prompt changes, resource changes)
- Report: text rendering, JSON marshaling, SARIF format
- Transport: stdio (echo server), HTTP (mock server)
- Shadow: conflict detection, multi-server comparison
- Client: initialize, list tools/prompts/resources, error handling

Untested: `main()` (os.Exit blocking), `runShadowCheck` (needs multiple baseline files), SSE transport (needs live SSE server).

## Dependencies

- Go stdlib only. No external dependencies.
