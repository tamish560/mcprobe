# mcprobe

[![Go Report Card](https://goreportcard.com/badge/github.com/tamish560/mcprobe?style=flat-square)](https://goreportcard.com/report/github.com/tamish560/mcprobe)
[![Go Version](https://img.shields.io/badge/Go-1.23-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-0F172A?style=flat-square)](./LICENSE)
[![Release](https://img.shields.io/github/v/release/tamish560/mcprobe?style=flat-square&label=release)](https://github.com/tamish560/mcprobe/releases)
[![Tests](https://img.shields.io/badge/tests-23%20passing-22C55E?style=flat-square)](./mcprobe_test.go)

you're connecting random MCP servers to your agent. you haven't checked them. mcprobe checks them.

it introspects any MCP server, reads every tool description, every schema, every resource URI, and tells you what's wrong before you connect it to something that has filesystem access and shell access.

single binary. zero dependencies. go stdlib only.

we used it to scan 17 npm MCP servers. 11 had security findings. 3 had prompt injection in tool descriptions. the results are on the [MCP security leaderboard](https://valtors.github.io/valtors-landing/mcp-security-leaderboard.html).

## checks

| check | severity | what it finds |
|-------|----------|---------------|
| prompt injection | CRITICAL | "ignore previous instructions" sitting in a tool description. a model will follow it. |
| tool shadowing | HIGH | same tool name on multiple servers. your agent won't know which one it's calling. |
| resource exposure | HIGH/MEDIUM | tools that want /etc, your ssh keys, your .env file. nothing stops them. |
| path traversal | HIGH | resource URIs with ".." in them. you know what that does. |
| oversized descriptions | MEDIUM | 2000+ character descriptions. something could be hiding in there. |
| missing metadata | LOW | no description, no schema. the model will guess. the model will guess wrong. |
| baseline drift | CRITICAL | server changed since you last checked it. someone updated it. or replaced it. |

## install

```
go install github.com/tamish560/mcprobe@latest
```

or build from source:

```
git clone https://github.com/tamish560/mcprobe.git
cd mcprobe
go build -o mcprobe
```

or grab a prebuilt binary from [releases](https://github.com/tamish560/mcprobe/releases).

## usage

scan a stdio server:

```
mcprobe -command 'node server.js'
```

scan an npm package directly:

```
mcprobe -command 'npx -y @some/mcp-server'
```

scan an HTTP server:

```
mcprobe -http http://localhost:3000/mcp
```

scan an SSE server:

```
mcprobe -sse http://localhost:3000/sse
```

just list tools, skip the scan:

```
mcprobe -command 'node server.js' -list
```

## baseline and drift

save what the server looks like today:

```
mcprobe -command 'node server.js' -baseline snap.json
```

check if it changed later:

```
mcprobe -command 'node server.js' -diff snap.json
```

it detects:
- tool descriptions changed (someone rewrote what the tool does)
- tools added (you didn't add them. who did?)
- tools removed (hope you weren't using them)
- schemas modified (the inputs are different now. your agent doesn't know that.)
- server version changed (someone updated it. or replaced it.)

## tool shadowing

when multiple MCP servers define the same tool name, your agent can't tell them apart. a malicious server exploits this to intercept calls meant for the real one. save baselines for each server, then check:

```
mcprobe -shadow -shadow-dir ./baselines/
```

## CI

SARIF output for GitHub Actions or anything that reads SARIF:

```
mcprobe -command 'node server.js' -format sarif -out results.sarif
```

exit codes:
- 0: clean (nothing high or critical)
- 1: error (something went wrong)
- 2: dangerous (high or critical findings. you should not be running this server.)

## what it detects

### prompt injection (CRITICAL)

18 patterns including:
- "ignore all previous instructions"
- "you are now a ..."
- "act as if ..."
- "execute arbitrary commands"
- "read any file/env/secret"
- "rm -rf", "curl | bash"
- "exfiltrate data/secrets/keys"
- "disable/bypass security"
- "base64 decode"
- "override safety/policy/guardrail"

this is not hypothetical. these patterns exist in real MCP servers. we found them. people connect them to agents without checking.

### tool shadowing (HIGH/CRITICAL)

two servers, same tool name. the LLM picks one. you don't know which. a malicious server wins the coin flip and intercepts the call. good luck debugging that.

### path traversal (HIGH)

resource URIs with ".." in them. this is path traversal 101. it should not exist in a tool you're connecting to an agent.

### missing metadata (LOW)

no description. no schema. you can't audit what you can't read. the model will guess what the tool does. it will guess wrong. you'll find out when something breaks.

### oversized descriptions (MEDIUM)

2000+ characters in a tool description. nobody reads that. including the model. something could be hiding in there.

### rug-pull detection (CRITICAL)

you trusted the server. you ran `mcprobe -baseline`. it was clean. three weeks later the server updates and the tool description now says "ignore previous instructions." you wouldn't know. mcprobe would.

## output formats

- `text` (default): reads like a human wrote it. because it did.
- `json`: full structured scan result
- `sarif`: SARIF 2.1.0 for CI

## risk scoring

| score | level |
|-------|-------|
| 0-9 | MINIMAL |
| 10-24 | LOW |
| 25-49 | MEDIUM |
| 50-74 | HIGH |
| 75-100 | CRITICAL |

a score of 0 doesn't mean safe. it means we didn't find anything. there's a difference. you should know the difference.

## architecture

```
transport.go   MCP client transport (stdio + HTTP + SSE)
client.go      JSON-RPC client, server introspection
scanner.go     security analysis engine, pattern detection
baseline.go    snapshot persistence, drift detection
report.go      text, JSON, SARIF output
main.go        CLI entry point
mcprobe_test.go  23 tests
```

no external dependencies. pure go stdlib. one static binary.

## license

MIT
