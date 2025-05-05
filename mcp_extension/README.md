# Snyk MCP experimental

MCP (Model Context Protocol) is an open protocol that standardizes how applications share context with large language models.

MCP can support AI systems with the context needed to generate accurate and relevant responses for use cases where the AI systems do not have the context, by integrating the AI systems with tools and platforms that have specific capabilities. You can integrate Snyk MCP into certain AI-enabled security tools to provide Snyk security context.

## Snyk MCP server

Snyk is introducing an MCP server as part of the Snyk CLI. This will allow MCP-enabled security tools to integrate Snyk security scanning capabilities directly, thus bridging the gap between security scanning and emerging AI-assisted workflows.

In environments or applications that use MCP, you can use the `snyk mcp` CLI command to:

* Invoke Snyk scans:\
  Trigger CLI security scans for code, dependencies, or configurations in your codebase in your current MCP context.
* Retrieve results:\
  Obtain Snyk security findings directly in your MCP-enabled tool or environment.

To use the Snyk MCP server, download and install the Snyk CLI [v1.1296.2](https://github.com/snyk/cli/releases/tag/v1.1296.2) or later following the steps on the [installation page](install-or-update-the-snyk-cli/). No other dependencies are needed. Snyk recommends always using the latest version of the CLI.

The `snyk mcp` command is available in Early Access, under the `--experimental` flag for the following reasons:

* MCP is a new and evolving standard.
* The `snyk mcp` command is an early implementation of integrating Snyk security scanning into the MCP-enabled environment.
* Snyk wants to gather feedback on the benefits of MCP as an integration pattern for Snyk security.

Because the `snyk mcp` command is an experimental feature, the specific usage, parameters, and output related to this command may evolve as both MCP and this Snyk integration mature. Changes are possible before a general release.

## Starting the Snyk MCP server

To start the Snyk MCP server, use the `snyk mcp` command for a supported transport type, `stdio` or `sse` as follows:

`snyk mcp -t sse --experimental` - Start the Snyk MCP server using `sse`, HTTP Server-Sent Events) Transport. The available endpoint is `/sse`.

`snyk mcp -t stdio --experimental` - Start the Snyk MCP server using `stdio`, Stdio (Standard IO) Transport.

## Snyk security tools that are available with MCP

&#x20;The Snyk MCP server supports integrating the following Snyk security tools into an AI system:

* `snyk_sca_test` (Open Source scans)
* `snyk_code_test` (Code scans)
* `snyk_auth` (authentication)
* `snyk_logout` (logout)
* `snyk_auth_status` (authentication status check)
* `snyk_version` (version information)

## Environment variables for MCP

You can set CLI environment variables for the MCP server in the following ways:

* In the MCP server configuration file (whether in your IDE or on the MCP host)
* Directly on your system

For a full list of supported CLI environment variables, see [Environment variables for Snyk CLI](configure-the-snyk-cli/environment-variables-for-snyk-cli.md).

## MCP setup examples using the `mcpconfig.json` file

To add an MCP server to an AI system, check the documentation for the AI system where you plan to integrate Snyk and review the specific MCP instructions. Examples of systems where you can integrate Snyk include [Windsurf's MCP](https://docs.windsurf.com/windsurf/mcp), [Qodo's MCP support](https://docs.qodo.ai/qodo-documentation/qodo-gen/qodo-gen-chat/agentic-mode/agentic-tools-mcps), and [VS Code MCP support](https://code.visualstudio.com/docs/copilot/chat/mcp-servers).

The following examples show how to add the Snyk MCP server in the `mcpconfig.json` file for each transport type. This method requires that the Snyk CLI is in your system path and can be invoked with the command `snyk`. If the CLI is not in your system path, you can provide the full path to the CLI.

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
      ],
      "env":{
      // optional CLI environment variables, e.g. SNYK_CFG_ORG, SNYK_TOKEN
      }
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


SSE transport supports running the MCP server locally only. SSe does not support remote or hosted configurations.


## Setting up Qodo integration

1. Select the Agentic option for interacting with Qodo.

<div data-full-width="true"><figure><img src="../.gitbook/assets/Screenshot 2025-04-24 at 09.56.26.png" alt="" width="563"><figcaption><p>Select Agentic</p></figcaption></figure></div>

2. Click **Connect more tools**.

<figure><img src="../.gitbook/assets/Screenshot 2025-04-24 at 09.56.52.png" alt="" width="561"><figcaption><p>Connect more tools</p></figcaption></figure>

3. Click the **+** button to add a new MCP server.

<figure><img src="../.gitbook/assets/Screenshot 2025-04-24 at 09.57.06.png" alt="" width="563"><figcaption><p>Plus button for Agentic Tools (MCP)</p></figcaption></figure>

4. Provide the required details for the Snyk MCP Server:

* The MCP Server name
* The path to the Snyk CLI
* The Snyk MCP command to [start the MCP server](snyk-mcp-experimental.md#starting-the-snyk-mcp-server).

<figure><img src="../.gitbook/assets/Screenshot 2025-04-24 at 10.01.57.png" alt="" width="563"><figcaption><p>MCP server details</p></figcaption></figure>

5. Snyk Security should now be visible in your list of tools. You can expand the Snyk Security list to see the tools available with the Snyk MCP integration.

<figure><img src="../.gitbook/assets/Screenshot 2025-04-24 at 10.02.14.png" alt="" width="563"><figcaption><p>Tools available with Snyk MCP integraton</p></figcaption></figure>

6. At this point, start interacting with the Snyk MCP and ask for your code to be scanned.

<figure><img src="../.gitbook/assets/Screenshot 2025-04-24 at 10.02.59.png" alt="" width="563"><figcaption><p>Request to scan your code</p></figcaption></figure>
