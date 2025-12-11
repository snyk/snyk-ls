package mcp

import (
	"strings"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
	mcpconfig "github.com/snyk/studio-mcp/pkg/mcp"
	mcp "github.com/snyk/studio-mcp/shared"
)

func CallMcpConfigWorkflow(c *config.Config, notifier notification.Notifier, configureMcp bool, configureRules bool) {
	logger := c.Logger().With().Str("method", "callMcpConfigWorkflow").Logger()

	registerCallback := func(cmd string, args []string, env map[string]string) error {
		notifier.Send(types.SnykRegisterMcpParams{
			Command: cmd,
			Args:    args,
			Env:     env,
		})
		return nil
	}

	engine := c.Engine()
	trustedFolders := c.TrustedFolders()
	trustedFoldersStrSlice := make([]string, len(trustedFolders))
	for i, f := range trustedFolders {
		trustedFoldersStrSlice[i] = string(f)
	}
	trustedFoldersStr := strings.Join(trustedFoldersStrSlice, ";")

	trustedWorkspaceFolders, _ := c.Workspace().GetFolderTrust()
	for _, f := range trustedWorkspaceFolders {
		mcpConfig := engine.GetConfiguration().Clone()
		mcpConfig.Set(mcp.McpRegisterCallbackParam, mcp.McpRegisterCallback(registerCallback))
		mcpConfig.Set(mcp.ToolNameParam, c.IdeName())
		mcpConfig.Set(mcp.IdeConfigPathParam, c.IdeName())
		mcpConfig.Set(mcp.TrustedFoldersParam, trustedFoldersStr)
		if c.GetSecureAtInceptionExecutionFrequency() == "Smart Scan" {
			mcpConfig.Set(mcp.RuleTypeParam, mcp.RuleTypeSmart)
		} else if c.GetSecureAtInceptionExecutionFrequency() == "On Code Generation" {
			mcpConfig.Set(mcp.RuleTypeParam, mcp.RuleTypeAlwaysApply)
		}

		if (c.GetSecureAtInceptionExecutionFrequency() == "Manual" && configureRules) || (!c.IsAutoConfigureMcpEnabled() && configureMcp) {
			mcpConfig.Set(mcp.RemoveParam, true)
		}

		mcpConfig.Set(mcp.RulesScopeParam, mcp.RulesWorkspaceScope)
		mcpConfig.Set(mcp.WorkspacePathParam, string(f.Path()))

		mcpConfig.Set(mcp.ConfigureMcpParam, configureMcp)
		mcpConfig.Set(mcp.ConfigureRulesParam, configureRules)

		_, err := c.Engine().InvokeWithConfig(mcpconfig.WORKFLOWID_MCP_CONFIG, mcpConfig)
		if err != nil {
			logger.Err(err).Msg("failed to configure MCP")
		}
	}
}
