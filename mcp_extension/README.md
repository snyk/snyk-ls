# Snyk MCP - Early Access

MCP (Model Context Protocol) is an open protocol that standardizes how applications share context with large language models.

MCP can support AI systems with the context needed to generate accurate and relevant responses for use cases where the AI systems do not have the context, by integrating the AI systems with tools and platforms that have specific capabilities. You can integrate Snyk MCP into certain AI-enabled security tools to provide Snyk security context.

Snyk is introducing an MCP server as part of the Snyk CLI. This will allow MCP-enabled security tools to integrate Snyk security scanning capabilities directly, thus bridging the gap between security scanning and emerging AI-assisted workflows.

The `snyk mcp` command is available in Early Access for the following reasons:

* MCP is a new and evolving standard.
* The `snyk mcp` command is an early implementation of integrating Snyk security scanning into the MCP-enabled environment.
* Snyk wants to gather feedback on the benefits of MCP as an integration pattern for Snyk security.

Because the `snyk mcp` command is an Early Access feature, the specific usage, parameters, and output related to this command may evolve as both MCP and this Snyk integration mature. Changes are possible before a general release.

In environments or applications that use MCP, you can use the `snyk mcp` CLI command to:

* Invoke Snyk scans:\
  Trigger CLI security scans for code, dependencies, or configurations in your codebase in your current MCP context.
* Retrieve results:\
  Obtain Snyk security findings directly in your MCP-enabled tool or environment.

&#x20;The Snyk MCP server supports integrating the following Snyk security tools into an AI system:

* `snyk_sca_scan` (Open Source scan)
* `snyk_code_scan` (Code scan)
* `snyk_iac_scan` (IaC scan)
* `snyk_container_scan` (IaC scan)
* `snyk_sbom_scan` (SBOM file scan)
* `snyk_aibom` (Create AIBOM)
* `snyk_trust` (Trust a given folder before running a scan)
* `snyk_auth` (authentication)
* `snyk_logout` (logout)
* `snyk_auth_status` (authentication status check)
* `snyk_version` (version information)


Running `snyk_sca_scan` may execute third-party ecosystem tools (for example, Gradle or Maven) on your machine to fetch the project's dependency tree.

