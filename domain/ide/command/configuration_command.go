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
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
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
func constructSettingsFromConfig(engine workflow.Engine, configResolver types.ConfigResolverInterface) types.Settings {
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()
	// Extract CLI settings
	insecure := false
	cliPath := ""
	additionalOssParams := ""
	if engine != nil {
		insecure = conf.GetBool(configresolver.UserGlobalKey(types.SettingCliInsecure))
		cliPathVal := conf.GetString(configresolver.UserGlobalKey(types.SettingCliPath))
		if cliPathVal != "" {
			cliPath = filepath.Clean(cliPathVal)
		}
		if params, ok := conf.Get(configresolver.UserGlobalKey(types.SettingCliAdditionalOssParameters)).([]string); ok && len(params) > 0 {
			for _, param := range params {
				additionalOssParams += param + " "
			}
		}
	}

	// Get environment PATH
	envPath := conf.GetString("PATH")

	s := types.Settings{
		// Core Authentication
		Token:                   config.GetToken(conf),
		Endpoint:                conf.GetString(configresolver.UserGlobalKey(types.SettingApiEndpoint)),
		CliBaseDownloadURL:      conf.GetString(configresolver.UserGlobalKey(types.SettingBinaryBaseUrl)),
		Organization:            util.Ptr(types.GetGlobalOrganization(conf)),
		AuthenticationMethod:    config.GetAuthenticationMethodFromConfig(conf),
		AutomaticAuthentication: fmt.Sprintf("%v", conf.GetBool(configresolver.UserGlobalKey(types.SettingAutomaticAuthentication))),
		DeviceId:                conf.GetString(configresolver.UserGlobalKey(types.SettingDeviceId)),

		// CLI and Paths
		CliPath:                     cliPath,
		Path:                        envPath,
		ManageBinariesAutomatically: fmt.Sprintf("%v", conf.GetBool(configresolver.UserGlobalKey(types.SettingAutomaticDownload))),
		AdditionalParams:            additionalOssParams,

		// Security Settings
		Insecure: fmt.Sprintf("%v", insecure),

		// Initialize StoredFolderConfigs as empty slice
		StoredFolderConfigs: []types.FolderConfig{},
	}

	populateProductSettings(&s, conf)
	populateSecuritySettings(&s, conf)
	populateOperationalSettings(&s, conf)
	populateFeatureToggles(&s, conf)
	populateAdvancedSettings(&s, conf, logger)
	populatePointerFields(&s, conf)
	populateFolderConfigs(&s, conf, logger, engine, configResolver)

	return s
}

// populateProductSettings sets product activation flags
func populateProductSettings(s *types.Settings, conf configuration.Configuration) {
	s.ActivateSnykOpenSource = fmt.Sprintf("%v", conf.GetBool(configresolver.UserGlobalKey(types.SettingSnykOssEnabled)))
	s.ActivateSnykCode = fmt.Sprintf("%v", conf.GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)))
	s.ActivateSnykIac = fmt.Sprintf("%v", conf.GetBool(configresolver.UserGlobalKey(types.SettingSnykIacEnabled)))
	s.ActivateSnykSecrets = fmt.Sprintf("%v", conf.GetBool(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled)))
}

// populateSecuritySettings sets security-related configuration
func populateSecuritySettings(s *types.Settings, conf configuration.Configuration) {
	s.EnableTrustedFoldersFeature = fmt.Sprintf("%v", conf.GetBool(configresolver.UserGlobalKey(types.SettingTrustEnabled)))
	val, _ := conf.Get(configresolver.UserGlobalKey(types.SettingTrustedFolders)).([]types.FilePath)
	s.TrustedFolders = convertFilePathsToStrings(val)
}

// populateOperationalSettings sets operational configuration
func populateOperationalSettings(s *types.Settings, conf configuration.Configuration) {
	s.SendErrorReports = fmt.Sprintf("%v", conf.GetBool(configresolver.UserGlobalKey(types.SettingSendErrorReports)))
	if conf.GetBool(configresolver.UserGlobalKey(types.SettingScanAutomatic)) {
		s.ScanningMode = "auto"
	} else {
		s.ScanningMode = "manual"
	}
}

// populateFeatureToggles sets feature flag configuration
func populateFeatureToggles(s *types.Settings, conf configuration.Configuration) {
	s.EnableSnykLearnCodeActions = fmt.Sprintf("%v", conf.GetBool(configresolver.UserGlobalKey(types.SettingEnableSnykLearnCodeActions)))
	s.EnableSnykOSSQuickFixCodeActions = fmt.Sprintf("%v", conf.GetBool(configresolver.UserGlobalKey(types.SettingEnableSnykOssQuickFixActions)))
	s.EnableSnykOpenBrowserActions = fmt.Sprintf("%v", conf.GetBool(configresolver.UserGlobalKey(types.SettingEnableSnykOpenBrowserActions)))
	s.EnableDeltaFindings = fmt.Sprintf("%v", conf.GetBool(configresolver.UserGlobalKey(types.SettingScanNetNew)))
}

// populateAdvancedSettings sets advanced configuration
func populateAdvancedSettings(s *types.Settings, conf configuration.Configuration, logger *zerolog.Logger) {
	s.SnykCodeApi = getSnykCodeApiUrl(conf, logger)
	s.IntegrationName = conf.GetString(configuration.INTEGRATION_ENVIRONMENT)
	s.IntegrationVersion = conf.GetString(configuration.INTEGRATION_ENVIRONMENT_VERSION)
	s.OsPlatform = conf.GetString(configresolver.UserGlobalKey(types.SettingOsPlatform))
	s.OsArch = conf.GetString(configresolver.UserGlobalKey(types.SettingOsArch))
	s.RuntimeName = conf.GetString(configresolver.UserGlobalKey(types.SettingRuntimeName))
	s.RuntimeVersion = conf.GetString(configresolver.UserGlobalKey(types.SettingRuntimeVersion))
	s.RequiredProtocolVersion = conf.GetString(configresolver.UserGlobalKey(types.SettingClientProtocolVersion))
}

// populatePointerFields sets pointer-based configuration fields
func populatePointerFields(s *types.Settings, conf configuration.Configuration) {
	filterSeverity := config.GetFilterSeverity(conf)
	s.FilterSeverity = &filterSeverity

	issueViewOptions := config.GetIssueViewOptions(conf)
	s.IssueViewOptions = &issueViewOptions

	hoverVerbosity := conf.GetInt(configresolver.UserGlobalKey(types.SettingHoverVerbosity))
	s.HoverVerbosity = &hoverVerbosity

	riskScoreThreshold := conf.GetInt(configresolver.UserGlobalKey(types.SettingRiskScoreThreshold))
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

		// Clone the stored config so we don't modify the original
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
		types.SettingEnabledSeverities,
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
