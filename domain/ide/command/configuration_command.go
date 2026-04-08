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
	"github.com/snyk/snyk-ls/internal/util"
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

	settings := constructSettingsFromConfig(cmd.engine, cmd.configResolver)

	renderer, err := infraconfig.NewConfigHtmlRenderer(cmd.engine)
	if err != nil {
		return nil, fmt.Errorf("failed to create config renderer: %w", err)
	}

	htmlContent := renderer.GetConfigHtml(settings)
	if htmlContent == "" {
		return nil, fmt.Errorf("failed to generate config html")
	}

	cmd.logger.Debug().Str("method", method).Msg("returning configuration HTML")

	// Return the HTML content directly for the client to display
	return htmlContent, nil
}

// constructSettingsFromConfig reconstructs a Settings object from the active configuration.
// Boolean and integer values are converted to strings as per types.Settings definition.
// Uses ConfigResolver for all reads to ensure correct precedence resolution.
func constructSettingsFromConfig(engine workflow.Engine, r types.ConfigResolverInterface) types.Settings {
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()

	cliPath := ""
	if cliPathVal := r.GetString(types.SettingCliPath, nil); cliPathVal != "" {
		cliPath = filepath.Clean(cliPathVal)
	}
	additionalOssParams := ""
	if params := r.GetStringSlice(types.SettingCliAdditionalOssParameters, nil); len(params) > 0 {
		for _, param := range params {
			additionalOssParams += param + " "
		}
	}

	s := types.Settings{
		Token:                       config.GetToken(conf),
		Endpoint:                    r.GetString(types.SettingApiEndpoint, nil),
		CliBaseDownloadURL:          r.GetString(types.SettingBinaryBaseUrl, nil),
		Organization:                util.Ptr(r.GetString(types.SettingOrganization, nil)),
		AuthenticationMethod:        types.AuthenticationMethod(r.GetString(types.SettingAuthenticationMethod, nil)),
		AutomaticAuthentication:     fmt.Sprintf("%v", r.GetBool(types.SettingAutomaticAuthentication, nil)),
		DeviceId:                    r.GetString(types.SettingDeviceId, nil),
		CliPath:                     cliPath,
		Path:                        conf.GetString("PATH"),
		ManageBinariesAutomatically: fmt.Sprintf("%v", r.GetBool(types.SettingAutomaticDownload, nil)),
		AdditionalParams:            additionalOssParams,
		Insecure:                    fmt.Sprintf("%v", r.GetBool(types.SettingCliInsecure, nil)),
		StoredFolderConfigs:         []types.FolderConfig{},
	}

	populateProductSettings(&s, r)
	populateSecuritySettings(&s, r)
	populateOperationalSettings(&s, r)
	populateFeatureToggles(&s, r)
	populateAdvancedSettings(&s, conf, r, logger)
	populatePointerFields(&s, r)
	populateFolderConfigs(&s, conf, logger, engine, r)

	return s
}

func populateProductSettings(s *types.Settings, r types.ConfigResolverInterface) {
	s.ActivateSnykOpenSource = fmt.Sprintf("%v", r.GetBool(types.SettingSnykOssEnabled, nil))
	s.ActivateSnykCode = fmt.Sprintf("%v", r.GetBool(types.SettingSnykCodeEnabled, nil))
	s.ActivateSnykIac = fmt.Sprintf("%v", r.GetBool(types.SettingSnykIacEnabled, nil))
	s.ActivateSnykSecrets = fmt.Sprintf("%v", r.GetBool(types.SettingSnykSecretsEnabled, nil))
}

func populateSecuritySettings(s *types.Settings, r types.ConfigResolverInterface) {
	s.EnableTrustedFoldersFeature = fmt.Sprintf("%v", r.GetBool(types.SettingTrustEnabled, nil))
	val, _ := r.GetValue(types.SettingTrustedFolders, nil)
	if folders, ok := val.([]types.FilePath); ok {
		s.TrustedFolders = convertFilePathsToStrings(folders)
	}
}

func populateOperationalSettings(s *types.Settings, r types.ConfigResolverInterface) {
	s.SendErrorReports = fmt.Sprintf("%v", r.GetBool(types.SettingSendErrorReports, nil))
	if r.GetBool(types.SettingScanAutomatic, nil) {
		s.ScanningMode = "auto"
	} else {
		s.ScanningMode = "manual"
	}
}

func populateFeatureToggles(s *types.Settings, r types.ConfigResolverInterface) {
	s.EnableSnykLearnCodeActions = fmt.Sprintf("%v", r.GetBool(types.SettingEnableSnykLearnCodeActions, nil))
	s.EnableSnykOSSQuickFixCodeActions = fmt.Sprintf("%v", r.GetBool(types.SettingEnableSnykOssQuickFixActions, nil))
	s.EnableSnykOpenBrowserActions = fmt.Sprintf("%v", r.GetBool(types.SettingEnableSnykOpenBrowserActions, nil))
	s.EnableDeltaFindings = fmt.Sprintf("%v", r.GetBool(types.SettingScanNetNew, nil))
}

func populateAdvancedSettings(s *types.Settings, conf configuration.Configuration, r types.ConfigResolverInterface, logger *zerolog.Logger) {
	s.SnykCodeApi = getSnykCodeApiUrl(conf, logger)
	s.IntegrationName = conf.GetString(configuration.INTEGRATION_ENVIRONMENT)
	s.IntegrationVersion = conf.GetString(configuration.INTEGRATION_ENVIRONMENT_VERSION)
	s.OsPlatform = r.GetString(types.SettingOsPlatform, nil)
	s.OsArch = r.GetString(types.SettingOsArch, nil)
	s.RuntimeName = r.GetString(types.SettingRuntimeName, nil)
	s.RuntimeVersion = r.GetString(types.SettingRuntimeVersion, nil)
	s.RequiredProtocolVersion = r.GetString(types.SettingClientProtocolVersion, nil)
}

func populatePointerFields(s *types.Settings, r types.ConfigResolverInterface) {
	hoverVerbosity := r.GetInt(types.SettingHoverVerbosity, nil)
	s.HoverVerbosity = &hoverVerbosity

	riskScoreThreshold := r.GetInt(types.SettingRiskScoreThreshold, nil)
	s.RiskScoreThreshold = &riskScoreThreshold
}

// populateFolderConfigs populates folder-specific configuration with effective values
func populateFolderConfigs(s *types.Settings, conf configuration.Configuration, logger *zerolog.Logger, engine workflow.Engine, configResolver types.ConfigResolverInterface) {
	ws := config.GetWorkspace(conf)
	if ws == nil {
		return
	}

	resolver := configResolver

	for _, f := range ws.Folders() {
		storedFc := config.GetFolderConfigFromEngine(engine, configResolver, f.Path(), logger)
		if storedFc == nil {
			continue
		}

		// Clone the folderConfig so we don't modify the original
		fc := *storedFc

		// Compute EffectiveConfig for org-scope settings if resolver is available
		if resolver != nil {
			fc.ConfigResolver = resolver
			fc.EffectiveConfig = computeEffectiveConfig(&fc)
		}

		s.StoredFolderConfigs = append(s.StoredFolderConfigs, fc)
	}
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

// getSnykCodeApiUrl returns the Snyk Code API URL based on the configuration
func getSnykCodeApiUrl(conf configuration.Configuration, logger *zerolog.Logger) string {
	url, err := config.GetCodeApiUrlFromCustomEndpoint(conf, nil, logger)
	if err != nil || url == "" {
		return "https://deeproxy.snyk.io"
	}
	return url
}
