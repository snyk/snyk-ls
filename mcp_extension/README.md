# Snyk MCP experimental

MCP (Model Context Protocol) is an open protocol that standardizes how applications share context with Large Language Models.

MCP can support AI systems with the context needed to generate accurate and relevant responses for use cases where the AI systems do not have the context, by integrating the AI systems with tools and platforms that have specific additional capabilities, in this case, Snyk security.

## Snyk MCP server

To bridge the gap between security scanning and emerging AI-assisted workflows, Snyk is introducing an MCP server as part of the Snyk CLI. This will allow MCP-enabled tools and contexts to integrate Snyk security scanning capabilities directly.

In environments or applications that use MCP, you can use the `snyk mcp` CLI command to:

- Invoke Snyk scans:\
  Trigger security scans for code, dependencies, or configurations in your codebase in your current MCP context.
- Retrieve results:\
  Obtain Snyk security findings directly in your MCP-enabled tool or environment.

To use the Snyk MCP server, download and install the Snyk CLI [v1.1296.2](https://github.com/snyk/cli/releases/tag/v1.1296.2) or later following the steps on the [installation page](install-or-update-the-snyk-cli/). No other dependencies are needed. Snyk recommends always using the latest version of the CLI.

The `snyk mcp` command is available in Early Access, under the `--experimental` flag for the following reasons:

- MCP is a new and evolving standard.
- The `snyk mcp` command is an early implementation of integrating Snyk security scanning into the MCP ecosystem.
- Snyk wants to gather feedback on the benefits of MCP as an integration pattern for Snyk security.

Because the `snyk mcp` command is an experimental feature, the specific usage, parameters, and output related to this command may evolve as both MCP and this Snyk integration mature. Changes are possible before a general release.

## Starting the Snyk MCP server

To start the Snyk MCP server, use the `snyk mcp` command for a supported transport type, `stdio` or `sse` as follows:

`snyk mcp -t sse --experimental` - Start the Snyk MCP server using SSE (HTTP Server-Sent Events). Transport. The available endpoint is `/sse`&#x20;

`snyk mcp -t stdio --experimental` - Start the Snyk MCP server using Stdio (Standard IO) Transport.

## Snyk security tools available with MCP

&#x20;The Snyk MCP server supports integrating the following Snyk security tools into an AI system:

- `snyk_sca_test` (Open Source scans)
- `snyk_code_test` (Code scans)
- `snyk_auth` (authentication)
- `snyk_logout` (logout)
- `snyk_auth_status` (authentication status check)
- `snyk_version` (version information)

## MCP setup examples

To add an MCP server, check the documentation for the AI system where you plan to integrate Snyk and review the specific MCP instructions. Examples of systems where you can integrate Snyk include [Windsurf's MCP](https://docs.windsurf.com/windsurf/mcp), [Qodo's MCP support](https://docs.qodo.ai/qodo-documentation/qodo-gen/qodo-gen-chat/agentic-mode/agentic-tools-mcps), and [VS Code MCP support](https://code.visualstudio.com/docs/copilot/chat/mcp-servers).

You may need to create or modify an `mcpconfig.json` file. This assumes that the Snyk CLI is in your system path and can be invoked with the command `snyk`. If the CLI is not in your system path, you can provide the full path to the CLI.

The following examples show how to add the Snyk MCP server in the `mcpconfig.json` file for each transport type.

### Add the Snyk MCP server using `stdio` transport in your `mcpconfig.json` file

```
{
  "mcpServers": {
    "Snyk Security Scanner": {
      "command": "snyk",
      "args": [
        "mcp",
        "-t",
        "stdio",
        "--experimental"
      ]
    }
  }
}
```

### Add the Snyk MCP server using `sse` transport in your `mcpconfig.json` file

If your MCP Client expects a URL, then you will need to start the MCP server in your terminal first by running `snyk mcp -t sse --experimental`&#x20;

This will output the base URL for your local SSE server. The `sse` endpoint lives on `http://baseUrl/sse.`

```
{
  "mcpServers": {
    "Snyk Security Scanner": {
      "url": "http://baseUrl/sse",
    }
  }
}
```
