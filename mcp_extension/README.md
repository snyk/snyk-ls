# Snyk MCP Extension

## Overview

The MCP (Model Context Protocol) extension for Snyk enables integration with Anthropic's Claude AI models using the Model Context Protocol. This extension is part of the Snyk Language Server (Snyk-LS) and allows for programmatic interaction with Snyk's functionality through AI assistants.

MCP is an open protocol developed by Anthropic to provide language models with structured context, helping to create more effective AI assistants that can use tools and reference information.

## References

- [Anthropic Website](https://www.anthropic.com/)
- [Model Context Protocol (MCP) Specification](https://docs.anthropic.com/claude/docs/model-context-protocol-mcp)

## Features

- Supports multiple transport protocols (SSE, stdio)

## Supported Tools

The MCP extension provides access to the following Snyk tools:

| Tool Name | Description |
|-----------|-------------|
| snyk_sca_test | Run a SCA test on project dependencies to detect known vulnerabilities. Use this to scan open-source packages in supported ecosystems like npm, Maven, etc. Supports monorepo scanning via `--all-projects`. |
| snyk_code_test | Run a static application security test (SAST) on your source code to detect security issues like SQL injection, XSS, and hardcoded secrets. |
| snyk_version | Get Snyk CLI version. |
| snyk_auth | Authenticate with Snyk. |
| snyk_auth_status | Check Snyk authentication status. |
| snyk_logout | Log out from Snyk. |

## Usage

### Prerequisites

- The extension requires the Snyk CLI to be available
- It is currently marked as experimental

### Enabling the Extension

To enable the MCP extension, you must set the `--experimental` and `-t`flag:

```bash
snyk mcp --experimental -t stdio
```

### Configuration Options

| Option | Flag | Default | Description |
|--------|------|---------|-------------|
| Transport | `-t, --transport` | `sse` | **REQUIRED** - Sets the transport protocol (`sse` or `stdio`) |
| Experimental | `--experimental` | `false` | **REQUIRED** - Enables the experimental MCP command |

### Example Commands

```bash
# Start MCP with SSE transport
snyk mcp --experimental --transport sse

# Start MCP with stdio transport
snyk mcp --experimental --transport stdio
```
