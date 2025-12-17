/*
 * © 2025 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package mcp implements MCP configure workflow call
package mcp

import (
	"strings"

	mcpconfig "github.com/snyk/studio-mcp/pkg/mcp"
	mcpTypes "github.com/snyk/studio-mcp/shared"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)

const (
	SecureAtInceptionOnCodeGeneration = "On Code Generation"
	SecureAtInceptionSmartScan        = "Smart Scan"
	SecureAtInceptionManual           = "Manual"
)

func CallMcpConfigWorkflow(c *config.Config, notifier notification.Notifier, configureMcp bool, configureRules bool) {
	go func() {
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
			mcpConfig.Set(mcpTypes.McpRegisterCallbackParam, mcpTypes.McpRegisterCallback(registerCallback))
			mcpConfig.Set(mcpTypes.ToolNameParam, c.IdeName())
			mcpConfig.Set(mcpTypes.IdeConfigPathParam, c.IdeName())
			mcpConfig.Set(mcpTypes.TrustedFoldersParam, trustedFoldersStr)
			if c.GetSecureAtInceptionExecutionFrequency() == SecureAtInceptionSmartScan {
				mcpConfig.Set(mcpTypes.RuleTypeParam, mcpTypes.RuleTypeSmart)
			} else if c.GetSecureAtInceptionExecutionFrequency() == SecureAtInceptionOnCodeGeneration {
				mcpConfig.Set(mcpTypes.RuleTypeParam, mcpTypes.RuleTypeAlwaysApply)
			}

			if (c.GetSecureAtInceptionExecutionFrequency() == SecureAtInceptionManual && configureRules) || (!c.IsAutoConfigureMcpEnabled() && configureMcp) {
				mcpConfig.Set(mcpTypes.RemoveParam, true)
			}

			mcpConfig.Set(mcpTypes.RulesScopeParam, mcpTypes.RulesWorkspaceScope)
			mcpConfig.Set(mcpTypes.WorkspacePathParam, string(f.Path()))

			mcpConfig.Set(mcpTypes.ConfigureMcpParam, configureMcp)
			mcpConfig.Set(mcpTypes.ConfigureRulesParam, configureRules)

			_, err := c.Engine().InvokeWithConfig(mcpconfig.WORKFLOWID_MCP_CONFIG, mcpConfig)
			if err != nil {
				logger.Err(err).Msg("failed to configure MCP")
			}
		}
	}()
}
