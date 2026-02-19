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

	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/configuration"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

type configurationCommand struct {
	command        types.CommandData
	srv            types.Server
	logger         *zerolog.Logger
	c              *config.Config
	configResolver types.ConfigResolverInterface
}

func (cmd *configurationCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *configurationCommand) Execute(ctx context.Context) (any, error) {
	method := "configurationCommand.Execute"
	cmd.logger.Debug().Str("method", method).Msg("executing configuration command")

	settings := constructSettingsFromConfig(cmd.c, cmd.configResolver)

	renderer, err := configuration.NewConfigHtmlRenderer(cmd.c)
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
func constructSettingsFromConfig(c *config.Config, configResolver types.ConfigResolverInterface) types.Settings {
	// Extract CLI settings
	insecure := false
	cliPath := ""
	additionalOssParams := ""
	if c.CliSettings() != nil {
		insecure = c.CliSettings().Insecure
		cliPath = c.CliSettings().Path()
		if len(c.CliSettings().AdditionalOssParameters) > 0 {
			for _, param := range c.CliSettings().AdditionalOssParameters {
				additionalOssParams += param + " "
			}
		}
	}

	// Get environment PATH
	envPath := c.Engine().GetConfiguration().GetString("PATH")

	s := types.Settings{
		// Core Authentication
		Token:                   c.Token(),
		Endpoint:                c.Endpoint(),
		CliBaseDownloadURL:      c.CliBaseDownloadURL(),
		Organization:            util.Ptr(c.Organization()),
		AuthenticationMethod:    c.AuthenticationMethod(),
		AutomaticAuthentication: fmt.Sprintf("%v", c.AutomaticAuthentication()),
		DeviceId:                c.DeviceID(),

		// CLI and Paths
		CliPath:                     cliPath,
		Path:                        envPath,
		ManageBinariesAutomatically: fmt.Sprintf("%v", c.ManageBinariesAutomatically()),
		AdditionalParams:            additionalOssParams,

		// Security Settings
		Insecure: fmt.Sprintf("%v", insecure),

		// Initialize StoredFolderConfigs as empty slice
		StoredFolderConfigs: []types.FolderConfig{},
	}

	populateProductSettings(&s, c)
	populateSecuritySettings(&s, c)
	populateOperationalSettings(&s, c)
	populateFeatureToggles(&s, c)
	populateAdvancedSettings(&s, c)
	populatePointerFields(&s, c)
	populateStoredFolderConfigs(&s, c, configResolver)

	return s
}

// populateProductSettings sets product activation flags
func populateProductSettings(s *types.Settings, c *config.Config) {
	s.ActivateSnykOpenSource = fmt.Sprintf("%v", c.IsSnykOssEnabled())
	s.ActivateSnykCode = fmt.Sprintf("%v", c.IsSnykCodeEnabled())
	s.ActivateSnykIac = fmt.Sprintf("%v", c.IsSnykIacEnabled())
}

// populateSecuritySettings sets security-related configuration
func populateSecuritySettings(s *types.Settings, c *config.Config) {
	s.EnableTrustedFoldersFeature = fmt.Sprintf("%v", c.IsTrustedFolderFeatureEnabled())
	s.TrustedFolders = convertFilePathsToStrings(c.TrustedFolders())
}

// populateOperationalSettings sets operational configuration
func populateOperationalSettings(s *types.Settings, c *config.Config) {
	s.SendErrorReports = fmt.Sprintf("%v", c.IsErrorReportingEnabled())
	if c.IsAutoScanEnabled() {
		s.ScanningMode = "auto"
	} else {
		s.ScanningMode = "manual"
	}
}

// populateFeatureToggles sets feature flag configuration
func populateFeatureToggles(s *types.Settings, c *config.Config) {
	s.EnableSnykLearnCodeActions = fmt.Sprintf("%v", c.IsSnykLearnCodeActionsEnabled())
	s.EnableSnykOSSQuickFixCodeActions = fmt.Sprintf("%v", c.IsSnykOSSQuickFixCodeActionsEnabled())
	s.EnableSnykOpenBrowserActions = fmt.Sprintf("%v", c.IsSnykOpenBrowserActionEnabled())
	s.EnableDeltaFindings = fmt.Sprintf("%v", c.IsDeltaFindingsEnabled())
}

// populateAdvancedSettings sets advanced configuration
func populateAdvancedSettings(s *types.Settings, c *config.Config) {
	s.SnykCodeApi = getSnykCodeApiUrl(c)
	s.IntegrationName = c.IdeName()
	s.IntegrationVersion = c.IdeVersion()
	s.OsPlatform = c.OsPlatform()
	s.OsArch = c.OsArch()
	s.RuntimeName = c.RuntimeName()
	s.RuntimeVersion = c.RuntimeVersion()
	s.RequiredProtocolVersion = c.ClientProtocolVersion()
}

// populatePointerFields sets pointer-based configuration fields
func populatePointerFields(s *types.Settings, c *config.Config) {
	filterSeverity := c.FilterSeverity()
	s.FilterSeverity = &filterSeverity

	issueViewOptions := c.IssueViewOptions()
	s.IssueViewOptions = &issueViewOptions

	hoverVerbosity := c.HoverVerbosity()
	s.HoverVerbosity = &hoverVerbosity

	riskScoreThreshold := c.RiskScoreThreshold()
	s.RiskScoreThreshold = &riskScoreThreshold
}

// populateStoredFolderConfigs populates folder-specific configuration with effective values
func populateStoredFolderConfigs(s *types.Settings, c *config.Config, configResolver types.ConfigResolverInterface) {
	if c.Workspace() == nil {
		return
	}

	resolver := configResolver

	for _, f := range c.Workspace().Folders() {
		storedFc := c.FolderConfig(f.Path())
		if storedFc == nil {
			continue
		}

		// Clone the stored config so we don't modify the original
		fc := *storedFc

		// Compute EffectiveConfig for org-scope settings if resolver is available
		if resolver != nil {
			fc.EffectiveConfig = computeEffectiveConfig(resolver, &fc)
		}

		s.StoredFolderConfigs = append(s.StoredFolderConfigs, fc)
	}
}

// computeEffectiveConfig computes effective values for all org-scope settings
// that can be displayed/edited in the HTML settings page
func computeEffectiveConfig(resolver types.ConfigResolverInterface, fc *types.FolderConfig) map[string]types.EffectiveValue {
	effectiveConfig := make(map[string]types.EffectiveValue)

	// Org-scope settings that can be overridden per-folder
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
func getSnykCodeApiUrl(c *config.Config) string {
	url, err := c.GetCodeApiUrlFromCustomEndpoint(nil)
	if err != nil || url == "" {
		return "https://deeproxy.snyk.io"
	}
	return url
}
