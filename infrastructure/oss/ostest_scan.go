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

package oss

import (
	"context"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/envvars"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/internal/types"
)

func (cliScanner *CLIScanner) ostestScan(_ context.Context, path types.FilePath, cmd []string, workDir types.FilePath) ([]workflow.Data, error) {
	c := cliScanner.config
	logger := c.Logger().With().Str("method", "cliScanner.ostestScan").Logger()
	engine := c.Engine()
	gafConfig := engine.GetConfiguration().Clone()

	// load env from shell
	envvars.UpdatePath(c.GetUserSettingsPath(), true) // prioritize the user specified PATH over their SHELL's
	envvars.LoadConfiguredEnvironment(gafConfig.GetStringSlice(configuration.CUSTOM_CONFIG_FILES), string(workDir))

	gafConfig.Set(configuration.WORKING_DIRECTORY, string(workDir))
	gafConfig.Set(configuration.RAW_CMD_ARGS, cmd[1:])
	gafConfig.Set(configuration.INPUT_DIRECTORY, string(workDir))
	gafConfig.Set(configuration.ORGANIZATION, c.FolderOrganization(workDir))
	gafConfig.Set(configuration.WORKFLOW_USE_STDIO, false)

	// this is hard coded here, as the extension does not export its ID
	// see: https://github.com/snyk/cli-extension-os-flows/blob/main/internal/commands/ostest/workflow.go#L45
	testWorkFlowId := workflow.NewWorkflowIdentifier("test")

	// This cannot be canceled :(
	output, err := engine.InvokeWithConfig(testWorkFlowId, gafConfig)
	if err != nil {
		logger.Err(err).Msg("Error while scanning for OSS issues")
		cliScanner.errorReporter.CaptureErrorAndReportAsIssue(path, err)
		return nil, err
	}

	return output, nil
}

func processOsTestWorkFlowData(
	ctx context.Context,
	scanOutput []workflow.Data,
	packageIssueCache map[string][]types.Issue,
) ([]types.Issue, error) {
	var issues []types.Issue
	var err error
	for _, data := range scanOutput {
		if testResults, ok := data.GetPayload().([]testapi.TestResult); ok {
			for _, testResult := range testResults {
				issues, err = convertTestResultToIssues(ctx, testResult, packageIssueCache)
				if err != nil {
					return nil, fmt.Errorf("couldn't convert test result to issues: %w", err)
				}
			}
		}
	}
	return issues, nil
}
