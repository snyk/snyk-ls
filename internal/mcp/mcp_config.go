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

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
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

func CallMcpConfigWorkflow(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, notifier notification.Notifier, configureMcp bool, configureRules bool) {
	subLogger := logger.With().Str("method", "callMcpConfigWorkflow").Logger()

	registerCallback := func(cmd string, args []string, env map[string]string) error {
		notifier.Send(types.SnykRegisterMcpParams{
			Command: cmd,
			Args:    args,
			Env:     env,
		})
		return nil
	}

	val, _ := conf.Get(configresolver.UserGlobalKey(types.SettingTrustedFolders)).([]types.FilePath)
	trustedFolders := val
	trustedFoldersStrSlice := make([]string, len(trustedFolders))
	for i, f := range trustedFolders {
		trustedFoldersStrSlice[i] = string(f)
	}
	trustedFoldersStr := strings.Join(trustedFoldersStrSlice, ";")

	ws := config.GetWorkspace(conf)
	if ws == nil {
		return
	}
	trustedWorkspaceFolders, _ := ws.GetFolderTrust()
	for _, f := range trustedWorkspaceFolders {
		mcpConfig := engine.GetConfiguration().Clone()
		mcpConfig.Set(mcpTypes.McpRegisterCallbackParam, mcpTypes.McpRegisterCallback(registerCallback))
		mcpConfig.Set(mcpTypes.ToolNameParam, conf.GetString(configuration.INTEGRATION_ENVIRONMENT))
		mcpConfig.Set(mcpTypes.IdeConfigPathParam, conf.GetString(configuration.INTEGRATION_ENVIRONMENT))
		mcpConfig.Set(mcpTypes.TrustedFoldersParam, trustedFoldersStr)
		if conf.GetString(configresolver.UserGlobalKey(types.SettingSecureAtInceptionExecutionFreq)) == SecureAtInceptionSmartScan {
			mcpConfig.Set(mcpTypes.RuleTypeParam, mcpTypes.RuleTypeSmart)
		} else if conf.GetString(configresolver.UserGlobalKey(types.SettingSecureAtInceptionExecutionFreq)) == SecureAtInceptionOnCodeGeneration {
			mcpConfig.Set(mcpTypes.RuleTypeParam, mcpTypes.RuleTypeAlwaysApply)
		}

		isRemoveOperation := conf.GetString(configresolver.UserGlobalKey(types.SettingSecureAtInceptionExecutionFreq)) == SecureAtInceptionManual && configureRules
		if isRemoveOperation {
			mcpConfig.Set(mcpTypes.RemoveParam, true)
			// never remove MCP server configuration
			mcpConfig.Set(mcpTypes.ConfigureMcpParam, false)
		} else {
			mcpConfig.Set(mcpTypes.ConfigureMcpParam, configureMcp)
		}

		mcpConfig.Set(mcpTypes.RulesScopeParam, mcpTypes.RulesWorkspaceScope)
		mcpConfig.Set(mcpTypes.WorkspacePathParam, string(f.Path()))

		mcpConfig.Set(mcpTypes.ConfigureRulesParam, configureRules)

		go func() {
			_, err := engine.InvokeWithConfig(mcpconfig.WORKFLOWID_MCP_CONFIG, mcpConfig)

			if err != nil {
				subLogger.Err(err).Msg("failed to configure MCP")
			}
		}()
	}
}
