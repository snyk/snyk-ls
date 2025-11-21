package command

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/configuration"
	"github.com/snyk/snyk-ls/internal/types"
)

type configurationCommand struct {
	command types.CommandData
	srv     types.Server
	logger  *zerolog.Logger
	c       *config.Config
}

func (cmd *configurationCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *configurationCommand) Execute(ctx context.Context) (any, error) {
	method := "configurationCommand.Execute"
	cmd.logger.Debug().Str("method", method).Msg("executing configuration command")

	settings := constructSettingsFromConfig(cmd.c)

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
func constructSettingsFromConfig(c *config.Config) types.Settings {
	s := types.Settings{
		// Core Authentication
		Token:                   c.Token(),
		Endpoint:                c.Endpoint(),
		Organization:            c.Organization(),
		AuthenticationMethod:    c.AuthenticationMethod(),
		AutomaticAuthentication: fmt.Sprintf("%v", c.AutomaticAuthentication()),
		DeviceId:                c.DeviceID(),

		// Initialize FolderConfigs as empty slice
		FolderConfigs: []types.FolderConfig{},
	}

	populateProductSettings(&s, c)
	populateCliSettings(&s, c)
	populateSecuritySettings(&s, c)
	populateOperationalSettings(&s, c)
	populateFeatureToggles(&s, c)
	populateAdvancedSettings(&s, c)
	populatePointerFields(&s, c)
	populateFolderConfigs(&s, c)

	return s
}

// populateProductSettings sets product activation flags
func populateProductSettings(s *types.Settings, c *config.Config) {
	s.ActivateSnykOpenSource = fmt.Sprintf("%v", c.IsSnykOssEnabled())
	s.ActivateSnykCode = fmt.Sprintf("%v", c.IsSnykCodeEnabled())
	s.ActivateSnykIac = fmt.Sprintf("%v", c.IsSnykIacEnabled())
	s.ActivateSnykCodeSecurity = fmt.Sprintf("%v", c.IsSnykCodeSecurityEnabled())
	s.ActivateSnykCodeQuality = fmt.Sprintf("%v", !c.IsSnykCodeSecurityEnabled())
}

// populateCliSettings sets CLI-related configuration
func populateCliSettings(s *types.Settings, c *config.Config) {
	if c.CliSettings() != nil {
		s.Insecure = fmt.Sprintf("%v", c.CliSettings().Insecure)
		s.CliPath = c.CliSettings().Path()
		s.AdditionalParams = buildAdditionalOssParamsString(c.CliSettings().AdditionalOssParameters)
	} else {
		s.Insecure = "false"
		s.CliPath = ""
		s.AdditionalParams = ""
	}

	s.Path = c.Engine().GetConfiguration().GetString("PATH")
	s.ManageBinariesAutomatically = fmt.Sprintf("%v", c.ManageBinariesAutomatically())
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
	s.AdditionalEnv = "" // Not currently stored in config
}

// populatePointerFields sets pointer-based configuration fields
func populatePointerFields(s *types.Settings, c *config.Config) {
	filterSeverity := c.FilterSeverity()
	s.FilterSeverity = &filterSeverity

	issueViewOptions := c.IssueViewOptions()
	s.IssueViewOptions = &issueViewOptions

	hoverVerbosity := c.HoverVerbosity()
	s.HoverVerbosity = &hoverVerbosity

	outputFormat := c.Format()
	s.OutputFormat = &outputFormat
}

// populateFolderConfigs populates folder-specific configuration
func populateFolderConfigs(s *types.Settings, c *config.Config) {
	if c.Workspace() == nil {
		return
	}

	for _, f := range c.Workspace().Folders() {
		fc := types.FolderConfig{
			FolderPath: f.Path(),
		}

		// Merge with stored config if available
		if storedFc := c.FolderConfig(fc.FolderPath); storedFc != nil {
			fc.BaseBranch = storedFc.BaseBranch
			fc.LocalBranches = storedFc.LocalBranches
			fc.AdditionalParameters = storedFc.AdditionalParameters
			fc.ReferenceFolderPath = storedFc.ReferenceFolderPath
			fc.PreferredOrg = storedFc.PreferredOrg
			fc.AutoDeterminedOrg = storedFc.AutoDeterminedOrg
			fc.OrgMigratedFromGlobalConfig = storedFc.OrgMigratedFromGlobalConfig
			fc.OrgSetByUser = storedFc.OrgSetByUser
			fc.FeatureFlags = storedFc.FeatureFlags
			fc.SastSettings = storedFc.SastSettings
			fc.ScanCommandConfig = storedFc.ScanCommandConfig
		}

		s.FolderConfigs = append(s.FolderConfigs, fc)
	}
}

// buildAdditionalOssParamsString converts additional OSS parameters to a space-separated string
func buildAdditionalOssParamsString(params []string) string {
	if len(params) == 0 {
		return ""
	}
	result := ""
	for _, param := range params {
		result += param + " "
	}
	return result
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
