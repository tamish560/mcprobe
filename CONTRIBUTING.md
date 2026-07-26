# Contributing to mcprobe

Thanks for your interest in contributing. mcprobe is a security scanner for MCP servers, built with Go.

## Ways to Contribute

- **Bug fixes** - Check issues labeled `bug`
- **Features** - Check issues labeled `enhancement` or `good first issue`
- **Injection patterns** - Add new prompt injection and shadow tool detection
- **Report formats** - Improve SARIF, JSON, and text report output
- **Transport** - Add support for new MCP transports
- **Docs** - Improve README, add examples, write guides
- **Tests** - Add test coverage for scanner and report packages

## Setup

```bash
git clone https://github.com/tamish560/mcprobe.git
cd mcprobe
go mod tidy
go build .
```

## Development

```bash
# Build
go build .

# Run tests
go test ./... -count=1

# Scan a server
./mcprobe scan --stdio -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

## AI Agent Contribution Guide

If you use AI tools to contribute, document which tools you used and which parts they generated. Keep human review in the loop.

## License

By contributing, you agree that your contributions will be licensed under the MIT license.
