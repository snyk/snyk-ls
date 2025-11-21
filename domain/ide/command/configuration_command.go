package command

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/sourcegraph/go-lsp"

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

	uri := lsp.DocumentURI("snyk://settings")

	params := types.ShowDocumentParams{
		Uri:       uri,
		External:  false,
		TakeFocus: true,
	}

	cmd.logger.Debug().Str("method", method).Interface("params", params).Msg("sending showDocument request")
	_, err = cmd.srv.Callback(ctx, "window/showDocument", params)
	if err != nil {
		cmd.logger.Err(err).Msg("failed to send window/showDocument callback")
		return nil, err
	}

	return nil, nil
}

func constructSettingsFromConfig(c *config.Config) types.Settings {
	// Helper to reconstruct settings from the active config.
	// We convert boolean/int values to strings as per types.Settings definition.

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

	// Core settings
	s := types.Settings{
		// Core Authentication
		Token:                   c.Token(),
		Endpoint:                c.Endpoint(),
		Organization:            c.Organization(),
		AuthenticationMethod:    c.AuthenticationMethod(),
		AutomaticAuthentication: fmt.Sprintf("%v", c.AutomaticAuthentication()),
		DeviceId:                c.DeviceID(),

		// Product Activation
		ActivateSnykOpenSource:   fmt.Sprintf("%v", c.IsSnykOssEnabled()),
		ActivateSnykCode:         fmt.Sprintf("%v", c.IsSnykCodeEnabled()),
		ActivateSnykIac:          fmt.Sprintf("%v", c.IsSnykIacEnabled()),
		ActivateSnykCodeSecurity: fmt.Sprintf("%v", c.IsSnykCodeSecurityEnabled()),
		ActivateSnykCodeQuality:  fmt.Sprintf("%v", !c.IsSnykCodeSecurityEnabled()), // Quality is inverse of security-only mode

		// CLI and Paths
		CliPath:                     cliPath,
		Path:                        envPath,
		ManageBinariesAutomatically: fmt.Sprintf("%v", c.ManageBinariesAutomatically()),

		// Security Settings
		Insecure:                    fmt.Sprintf("%v", insecure),
		EnableTrustedFoldersFeature: fmt.Sprintf("%v", c.IsTrustedFolderFeatureEnabled()),
		TrustedFolders:              convertFilePathsToStrings(c.TrustedFolders()),

		// Operational Settings
		SendErrorReports: fmt.Sprintf("%v", c.IsErrorReportingEnabled()),
		ScanningMode:     "auto",

		// Feature Toggles
		EnableSnykLearnCodeActions:       fmt.Sprintf("%v", c.IsSnykLearnCodeActionsEnabled()),
		EnableSnykOSSQuickFixCodeActions: fmt.Sprintf("%v", c.IsSnykOSSQuickFixCodeActionsEnabled()),
		EnableSnykOpenBrowserActions:     fmt.Sprintf("%v", c.IsSnykOpenBrowserActionEnabled()),
		EnableDeltaFindings:              fmt.Sprintf("%v", c.IsDeltaFindingsEnabled()),

		// Advanced Settings
		SnykCodeApi:             getSnykCodeApiUrl(c),
		IntegrationName:         c.IdeName(),
		IntegrationVersion:      c.IdeVersion(),
		OsPlatform:              c.OsPlatform(),
		OsArch:                  c.OsArch(),
		RuntimeName:             c.RuntimeName(),
		RuntimeVersion:          c.RuntimeVersion(),
		RequiredProtocolVersion: c.ClientProtocolVersion(),
		AdditionalParams:        additionalOssParams,
		AdditionalEnv:           "", // Not currently stored in config

		// Initialize FolderConfigs as empty slice
		FolderConfigs: []types.FolderConfig{},
	}

	if !c.IsAutoScanEnabled() {
		s.ScanningMode = "manual"
	}

	// FilterSeverity
	filterSeverity := c.FilterSeverity()
	s.FilterSeverity = &filterSeverity

	// IssueViewOptions
	issueViewOptions := c.IssueViewOptions()
	s.IssueViewOptions = &issueViewOptions

	// HoverVerbosity
	hoverVerbosity := c.HoverVerbosity()
	s.HoverVerbosity = &hoverVerbosity

	// OutputFormat (not directly exposed, using empty string as default)
	outputFormat := c.Format()
	s.OutputFormat = &outputFormat

	// Populate FolderConfigs
	if c.Workspace() != nil {
		for _, f := range c.Workspace().Folders() {
			fc := types.FolderConfig{
				FolderPath: f.Path(),
			}
			// Try to get stored config to populate optional fields
			storedFc := c.FolderConfig(fc.FolderPath)
			if storedFc != nil {
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

	return s
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
