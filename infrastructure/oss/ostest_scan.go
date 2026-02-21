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

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/subosito/gotenv"

	"github.com/snyk/cli-extension-os-flows/pkg/flags"

	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/types"
)

var (
	getTestResultsFromWorkflowData = ufm.GetTestResultsFromWorkflowData
	convertTestResultToIssuesFn    = convertTestResultToIssues
)

func (cliScanner *CLIScanner) ostestScan(_ context.Context, pathToScan types.FilePath, cmd []string, folderConfig *types.FolderConfig, env gotenv.Env) ([]workflow.Data, error) {
	c := cliScanner.config
	workDir := folderConfig.FolderPath
	logger := c.Logger().With().
		Str("method", "cliScanner.ostestScan").
		Any("cmd", cmd).
		Str("workDir", string(workDir)).
		Str("pathToScan", string(pathToScan)).
		Logger()
	engine := c.Engine()
	gafConfig := engine.GetConfiguration().Clone()
	gafConfig.Set(configuration.WORKING_DIRECTORY, string(workDir))
	gafConfig.Set(configuration.INPUT_DIRECTORY, []string{string(workDir)})

	// Resolve organization for the scan
	folderOrg := c.FolderConfigOrganization(folderConfig)
	logger.Debug().
		Str("globalOrg", c.Organization()).
		Str("folderOrg", folderOrg).
		Msg("resolved folder organization, overriding global org parameter")
	gafConfig.Set(configuration.ORGANIZATION, folderOrg)

	// convert args to flagset
	args := cmd[1:]
	gafConfig.Set(configuration.RAW_CMD_ARGS, args)
	flagSet := flags.OSTestFlagSet()
	flagSet.ParseErrorsAllowlist.UnknownFlags = true
	err2 := flagSet.Parse(args)
	if err2 != nil {
		logger.Err(err2).Msg("Error parsing cmd args")
		return nil, err2
	}

	err2 = gafConfig.AddFlagSet(flagSet)
	if err2 != nil {
		logger.Err(err2).Msg("Error adding flag set")
		return nil, err2
	}

	gafConfig.Set(configuration.WORKFLOW_USE_STDIO, false)
	gafConfig.Set("no-output", true)

	// Propagate feature flags from folder config to GAF config so that the
	// cli-extension-os-flows routing (ShouldUseLegacyFlow) stays consistent
	// with the LS-side routing (shouldUseLegacyScan).
	propagateFeatureFlags(folderConfig, gafConfig)

	// set env to workflow config
	invocationEnv := make([]string, 0, len(env))
	for k, v := range env {
		invocationEnv = append(invocationEnv, k+"="+v)
	}
	gafConfig.Set(configuration.SUBPROCESS_ENVIRONMENT, invocationEnv)

	// this is hard coded here, as the extension does not export its ID
	// see: https://github.com/snyk/cli-extension-os-flows/blob/main/internal/commands/ostest/workflow.go#L45
	testWorkFlowId := workflow.NewWorkflowIdentifier("test")

	logger.Debug().Str("folderOrg", folderOrg).Msg("Invoking OSS scan workflow")
	// This cannot be canceled :(
	output, err := engine.InvokeWithConfig(testWorkFlowId, gafConfig)
	if err != nil {
		logger.Err(err).Msg("Error while scanning for OSS issues")
		cliScanner.errorReporter.CaptureErrorAndReportAsIssue(pathToScan, err)
		return nil, err
	}

	return output, nil
}

// lsToGAFFeatureFlagMap maps LS feature flag names to their GAF config equivalents
// used by cli-extension-os-flows for routing decisions.
var lsToGAFFeatureFlagMap = map[string]string{
	featureflag.UseExperimentalRiskScore:      "internal_snyk_cli_experimental_risk_score",
	featureflag.UseExperimentalRiskScoreInCLI: "internal_snyk_cli_experimental_risk_score_in_cli",
	featureflag.UseOsTest:                     "internal_snyk_cli_use_test_shim_for_os_cli_test",
}

func propagateFeatureFlags(folderConfig *types.FolderConfig, gafConfig configuration.Configuration) {
	for lsKey, gafKey := range lsToGAFFeatureFlagMap {
		gafConfig.Set(gafKey, folderConfig.FeatureFlags[lsKey])
	}
}

func processOsTestWorkFlowData(
	ctx context.Context,
	scanOutput []workflow.Data,
	packageIssueCache map[string][]types.Issue,
) ([]types.Issue, error) {
	var issues []types.Issue
	var err error
	for _, data := range scanOutput {
		testResults := getTestResultsFromWorkflowData(data)
		for _, testResult := range testResults {
			var testIssues []types.Issue
			testIssues, err = convertTestResultToIssuesFn(ctx, testResult, packageIssueCache)
			if err != nil {
				return nil, fmt.Errorf("couldn't convert test result to issues: %w", err)
			}
			issues = append(issues, testIssues...)
		}
	}
	return issues, nil
}
