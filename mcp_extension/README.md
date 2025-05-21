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

## MCP setup examples

To add an MCP server to an Agentic IDE, consult the documentation for the AI system where you plan to integrate Snyk and review the specific MCP instructions. Examples of systems where you can integrate Snyk include [Windsurf's MCP](https://docs.windsurf.com/windsurf/mcp), [Qodo's MCP support](https://docs.qodo.ai/qodo-documentation/qodo-gen/qodo-gen-chat/agentic-mode/agentic-tools-mcps), and [VS Code MCP support](https://code.visualstudio.com/docs/copilot/chat/mcp-servers).

### MCP setup examples using the `mcpconfig.json` file

This method can be used for to set up Windsurf's MCP, as one example. These example example show how to add the Snyk MCP server in the `mcpconfig.json` file for each transport type. This method requires that the Snyk CLI is in your system path and can be invoked with the command `snyk`. If the CLI is not in your system path, you can provide the full path to the CLI.

#### Add the Snyk MCP server using `stdio` transport in your `mcpconfig.json` file

```
{
  "mcpServers": {
    "Snyk Security Scanner": {
      "command": "/absolute/path/to/snyk",
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

#### Add the Snyk MCP server using `sse` transport in your `mcpconfig.json` file

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


### Qodo setup steps

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

## Troubleshooting for the Snyk MCP server

If you encounter issues with the Snyk MCP server or its integration, try the troubleshooting steps provided here.

### Ensure your Snyk CLI version is compatible

* After downloading or updating the CLI, run `snyk version`.
* The version must be ≥ v1.1296.2. Snyk recommends using the latest version.

### Verify Snyk CLI path and permissions

* If you have specified a direct path to the `snyk` executable in your `mcpconfig.json`  double-check that this path is correct.
* Ensure the Snyk CLI binary has execute permissions.

### Proxy configuration

* If you are behind a corporate proxy, ensure the `http_proxy` and `https_proxy` environment variables are correctly set and accessible to the Snyk CLI and MCP server process.

### Authentication issues

* Some MCP hosts (the client application integrating the Snyk MCP server) might restrict MCP server processes, which can interfere with the Snyk authentication flow (for example, browser-based login).
* Mitigation strategies
  * Try starting the Snyk MCP server in `sse` transport mode instead of `stdio`: `snyk mcp -t sse --experimental` and set the URL in your `mcpconfig.json` file.
  * Provide a Snyk authentication token directly using the `SNYK_TOKEN` environment variable.&#x20;

### Snyk Organization configuration

* If your Snyk account is part of multiple Organizations, or if scans are not appearing in the expected place, ensure the correct Snyk Organization is configured. You can set this using:
  * The command `snyk config set org=<YOUR_ORG_ID>`
  * The environment variable `SNYK_CFG_ORG=<YOUR_ORG_ID>`
* Verify the SSE Transport specifics (if using `snyk mcp -t sse`):
  * Firewall restrictions: Check to see if the local firewall might be blocking incoming connections to the port used by the Snyk MCP SSE server.
  * Local only: Remember that SSE transport supports running the MCP server locally only.

### Environment variable propagation

* Verify that the necessary environment variables (for example, `SNYK_TOKEN`, `SNYK_CFG_ORG`, proxy settings) are correctly propagated to the Snyk MCP server process.

### Basic repository scanning (crucial diagnostic)

* This is a key step for many issues. Before suspecting complex MCP integration problems, confirm that the Snyk CLI you are using to run the MCP server can scan your repository directly from your terminal.
* Navigate to the root directory of your Project and run:
  * `/path/to/your/snykCli test` (for open-source vulnerabilities)
  * `/path/to/your/snykCli code test` (for code issues)
* If these direct scans fail, resolve those issues first (for example, authentication, Organization settings, Snyk Code enablement for your Organization).

### Verbose logging and debugging

Use these suggestions to improve and expand on your Snyk CLI debug output to troubleshoot MCP-related issues:

* For more detailed Snyk CLI logs, which are useful whether you are starting the `snyk mcp` server or performing direct test scans (see [Basic repository scanning](snyk-mcp-experimental.md#basic-repository-scanning-crucial-diagnostic)), you can add verbosity parameters to your Snyk commands.\
  \
  These include using the `-d` or `--debug` flag for debug level output, for example:
  * `snyk mcp -t sse --experimental -d`
  * `snyk test -d`
  * `snyk code test -d`
* For even more granular, trace-level logging, you can use the `--log-level=trace` option or set the `SNYK_LOG_LEVEL=trace` environment variable:
  * `snyk mcp -t sse --experimental -d --log-level=trace`&#x20;
  * `SNYK_LOG_LEVEL=trace snyk mcp -t sse --experimental -d`
* Inspect the MCP client and host logs from your AI tool, IDE, or MCP client application. These logs might contain errors related to connecting to, or communicating with, the Snyk MCP server.
