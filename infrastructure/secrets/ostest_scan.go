package secrets

import (
	"context"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/envvars"
	pkgWorkflow "github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/internal/types"
)

func (cliScanner *CLIScanner) ostestScan(_ context.Context, path types.FilePath, cmd []string, workDir types.FilePath) ([]pkgWorkflow.Data, error) {
	c := cliScanner.config
	logger := c.Logger().With().Str("method", "cliScanner.ostestScan").Logger()
	engine := c.Engine()
	gafConfig := engine.GetConfiguration().Clone()

	// load env from shell
	envvars.UpdatePath(c.GetUserSettingsPath(), true) // prioritize the user specified PATH over their SHELL's
	envvars.LoadConfiguredEnvironment(gafConfig.GetStringSlice(configuration.CUSTOM_CONFIG_FILES), string(workDir))

	gafConfig.Set(configuration.WORKING_DIRECTORY, string(workDir))
	gafConfig.Set(configuration.RAW_CMD_ARGS, cmd[1:])
	gafConfig.Set(configuration.INPUT_DIRECTORY, []string{string(workDir)})
	gafConfig.Set(configuration.ORGANIZATION, c.FolderOrganization(workDir))
	gafConfig.Set(configuration.WORKFLOW_USE_STDIO, false)

	// this is hard coded here, as the extension does not export its ID.
	// https://github.com/snyk/cli-extension-secrets/blob/858d64ec07746889d417d1886538e647d51fe597/internal/commands/secretstest/workflow.go#L22C49-L22C63
	testWorkFlowId := pkgWorkflow.NewWorkflowIdentifier("secrets.test")

	// This cannot be canceled :(
	output, err := engine.InvokeWithConfig(testWorkFlowId, gafConfig)
	if err != nil {
		logger.Err(err).Msg("Error while scanning for Secrets issues")
		cliScanner.errorReporter.CaptureErrorAndReportAsIssue(path, err)
		return nil, err
	}

	return output, nil
}
