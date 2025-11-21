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
	if c.CliSettings() != nil {
		insecure = c.CliSettings().Insecure
	}

	s := types.Settings{
		Token:                       c.Token(),
		Endpoint:                    c.Endpoint(),
		Organization:                c.Organization(),
		Insecure:                    fmt.Sprintf("%v", insecure),
		ActivateSnykOpenSource:      fmt.Sprintf("%v", c.IsSnykOssEnabled()),
		ActivateSnykCode:            fmt.Sprintf("%v", c.IsSnykCodeEnabled()),
		ActivateSnykIac:             fmt.Sprintf("%v", c.IsSnykIacEnabled()),
		SendErrorReports:            fmt.Sprintf("%v", c.IsErrorReportingEnabled()),
		ManageBinariesAutomatically: fmt.Sprintf("%v", c.ManageBinariesAutomatically()),
		EnableTrustedFoldersFeature: fmt.Sprintf("%v", c.IsTrustedFolderFeatureEnabled()),
		ScanningMode:                "auto", // Default to auto if not exposed or different
		AuthenticationMethod:        c.AuthenticationMethod(),
	}

	if !c.IsAutoScanEnabled() {
		s.ScanningMode = "manual"
	}

	// FilterSeverity
	filterSeverity := c.FilterSeverity()
	s.FilterSeverity = &filterSeverity

	if c.CliSettings() != nil {
		s.CliPath = c.CliSettings().Path()
	}

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
				fc.AdditionalParameters = storedFc.AdditionalParameters
			}
			s.FolderConfigs = append(s.FolderConfigs, fc)
		}
	}

	return s
}
