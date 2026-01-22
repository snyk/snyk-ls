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
		Organization:            c.Organization(),
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

		// Initialize FolderConfigs as empty slice
		FolderConfigs: []types.FolderConfig{},
	}

	populateProductSettings(&s, c)
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

// populateFolderConfigs populates folder-specific configuration
func populateFolderConfigs(s *types.Settings, c *config.Config) {
	if c.Workspace() == nil {
		return
	}

	for _, f := range c.Workspace().Folders() {
		if storedFc := c.FolderConfig(f.Path()); storedFc != nil {
			s.FolderConfigs = append(s.FolderConfigs, *storedFc)
		}
	}
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
