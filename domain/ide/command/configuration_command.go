/*
 * © 2026 Snyk Limited
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

package command

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	infraconfig "github.com/snyk/snyk-ls/infrastructure/configuration"
	"github.com/snyk/snyk-ls/internal/types"
)

type configurationCommand struct {
	command        types.CommandData
	srv            types.Server
	logger         *zerolog.Logger
	engine         workflow.Engine
	configResolver types.ConfigResolverInterface
}

func (cmd *configurationCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *configurationCommand) Execute(ctx context.Context) (any, error) {
	method := "configurationCommand.Execute"
	cmd.logger.Debug().Str("method", method).Msg("executing configuration command")

	settings, folderConfigs := ConstructSettingsFromConfig(cmd.engine, cmd.configResolver)

	renderer, err := infraconfig.NewConfigHtmlRenderer(cmd.engine)
	if err != nil {
		return nil, fmt.Errorf("failed to create config renderer: %w", err)
	}

	htmlContent := renderer.GetConfigHtml(settings, folderConfigs)
	if htmlContent == "" {
		return nil, fmt.Errorf("failed to generate config html")
	}

	cmd.logger.Debug().Str("method", method).Msg("returning configuration HTML")

	// Return the HTML content directly for the client to display
	return htmlContent, nil
}

func ConstructSettingsFromConfig(engine workflow.Engine, r types.ConfigResolverInterface) (map[string]any, []types.FolderConfig) {
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()

	cliPath := ""
	if cliPathVal := r.GetString(types.SettingCliPath, nil); cliPathVal != "" {
		cliPath = filepath.Clean(cliPathVal)
	}

	severity := r.FilterSeverityForFolder(nil)
	issueView := r.IssueViewOptionsForFolder(nil)

	m := map[string]any{
		types.SettingToken:                  config.GetToken(conf),
		types.SettingApiEndpoint:            r.GetString(types.SettingApiEndpoint, nil),
		types.SettingAuthenticationMethod:   r.GetString(types.SettingAuthenticationMethod, nil),
		types.SettingProxyInsecure:          r.GetBool(types.SettingProxyInsecure, nil),
		types.SettingSnykOssEnabled:         r.GetBool(types.SettingSnykOssEnabled, nil),
		types.SettingSnykCodeEnabled:        r.GetBool(types.SettingSnykCodeEnabled, nil),
		types.SettingSnykIacEnabled:         r.GetBool(types.SettingSnykIacEnabled, nil),
		types.SettingSnykSecretsEnabled:     r.GetBool(types.SettingSnykSecretsEnabled, nil),
		types.SettingScanAutomatic:          r.GetBool(types.SettingScanAutomatic, nil),
		types.SettingScanNetNew:             r.GetBool(types.SettingScanNetNew, nil),
		types.SettingOrganization:           r.GetString(types.SettingOrganization, nil),
		types.SettingSeverityFilterCritical: severity.Critical,
		types.SettingSeverityFilterHigh:     severity.High,
		types.SettingSeverityFilterMedium:   severity.Medium,
		types.SettingSeverityFilterLow:      severity.Low,
		types.SettingIssueViewOpenIssues:    issueView.OpenIssues,
		types.SettingIssueViewIgnoredIssues: issueView.IgnoredIssues,
		types.SettingRiskScoreThreshold:     r.GetInt(types.SettingRiskScoreThreshold, nil),
		types.SettingCliPath:                cliPath,
		types.SettingAutomaticDownload:      r.GetBool(types.SettingAutomaticDownload, nil),
		types.SettingBinaryBaseUrl:          r.GetString(types.SettingBinaryBaseUrl, nil),
		types.SettingTrustedFolders:         trustedFoldersAsStrings(r),
	}

	folderConfigs := collectFolderConfigs(conf, logger, engine, r)
	return m, folderConfigs
}

func trustedFoldersAsStrings(r types.ConfigResolverInterface) []string {
	val, _ := r.GetValue(types.SettingTrustedFolders, nil)
	if folders, ok := val.([]types.FilePath); ok {
		return convertFilePathsToStrings(folders)
	}
	return []string{}
}

func collectFolderConfigs(conf configuration.Configuration, logger *zerolog.Logger, engine workflow.Engine, configResolver types.ConfigResolverInterface) []types.FolderConfig {
	ws := config.GetWorkspace(conf)
	if ws == nil {
		return []types.FolderConfig{}
	}

	var result []types.FolderConfig
	for _, f := range ws.Folders() {
		storedFc := config.GetFolderConfigFromEngine(engine, configResolver, f.Path(), logger)
		if storedFc == nil {
			continue
		}

		fc := *storedFc
		fc.ConfigResolver = configResolver
		fc.EffectiveConfig = computeEffectiveConfig(&fc)
		result = append(result, fc)
	}
	if result == nil {
		return []types.FolderConfig{}
	}
	return result
}

// computeEffectiveConfig computes effective values for all org-scope settings
// that can be displayed/edited in the HTML settings page
func computeEffectiveConfig(fc *types.FolderConfig) map[string]types.EffectiveValue {
	effectiveConfig := make(map[string]types.EffectiveValue)
	resolver := fc.ConfigResolver
	if resolver == nil {
		return effectiveConfig
	}

	orgScopeSettings := []string{
		types.SettingSeverityFilterCritical,
		types.SettingSeverityFilterHigh,
		types.SettingSeverityFilterMedium,
		types.SettingSeverityFilterLow,
		types.SettingIssueViewOpenIssues,
		types.SettingIssueViewIgnoredIssues,
		types.SettingScanAutomatic,
		types.SettingScanNetNew,
		types.SettingSnykCodeEnabled,
		types.SettingSnykOssEnabled,
		types.SettingSnykIacEnabled,
		types.SettingSnykSecretsEnabled,
		types.SettingRiskScoreThreshold,
	}

	for _, settingName := range orgScopeSettings {
		effectiveConfig[settingName] = resolver.GetEffectiveValue(settingName, fc)
	}

	return effectiveConfig
}

// convertFilePathsToStrings converts []types.FilePath to []string
func convertFilePathsToStrings(filePaths []types.FilePath) []string {
	result := make([]string, len(filePaths))
	for i, fp := range filePaths {
		result[i] = string(fp)
	}
	return result
}
