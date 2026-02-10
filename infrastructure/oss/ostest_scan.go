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
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/subosito/gotenv"

	"github.com/snyk/cli-extension-os-flows/pkg/flags"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/types"
)

var (
	getTestResultsFromWorkflowData = ufm.GetTestResultsFromWorkflowData
	convertTestResultToIssuesFn    = convertTestResultToIssues
)

// isLegacyCliStdoutData returns true if data is legacy CLI stdout (type id legacycli/stdout).
// Data identifiers use Scheme "did" (workflow.NewData overwrites the type id scheme to "did").
func isLegacyCliStdoutData(data workflow.Data) bool {
	id := data.GetIdentifier()
	if id == nil {
		return false
	}
	path := strings.TrimPrefix(id.Path, "/")
	return id.Scheme == "did" && id.Host == "legacycli" && path == "stdout"
}

func (cliScanner *CLIScanner) ostestScan(_ context.Context, path types.FilePath, cmd []string, workDir types.FilePath, env gotenv.Env) ([]workflow.Data, error) {
	c := cliScanner.config
	logger := c.Logger().With().
		Str("method", "cliScanner.ostestScan").
		Any("cmd", cmd).
		Str("workDir", string(workDir)).
		Str("path", string(path)).
		Logger()
	engine := c.Engine()
	gafConfig := engine.GetConfiguration().Clone()
	gafConfig.Set(configuration.WORKING_DIRECTORY, string(workDir))
	gafConfig.Set(configuration.INPUT_DIRECTORY, []string{string(workDir)})

	// Resolve organization for the scan
	folderOrg := c.FolderOrganization(workDir)
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
		cliScanner.errorReporter.CaptureErrorAndReportAsIssue(path, err)
		return nil, err
	}

	return output, nil
}

func processOsTestWorkFlowData(
	ctx context.Context,
	scanOutput []workflow.Data,
	packageIssueCache map[string][]types.Issue,
	c *config.Config,
	workDir types.FilePath,
	filePath types.FilePath,
	readFiles bool,
	learnService learn.Service,
	errorReporter error_reporting.ErrorReporter,
	format string,
) ([]types.Issue, error) {
	var issues []types.Issue
	logger := ctx2.LoggerFromContext(ctx).With().Str("method", "processOsTestWorkFlowData").Logger()
	for _, data := range scanOutput {
		if data.GetContentType() == content_type.UFM_RESULT {
			testResults := getTestResultsFromWorkflowData(data)
			for _, testResult := range testResults {
				testIssues, err := convertTestResultToIssuesFn(ctx, testResult, packageIssueCache)
				if err != nil {
					return nil, fmt.Errorf("couldn't convert test result to issues: %w", err)
				}
				issues = append(issues, testIssues...)
			}
			continue
		}

		// Legacy CLI stdout: identify by data type id (legacycli/stdout). Compare by URL components so we match
		// regardless of String() formatting (e.g. path with or without leading slash).
		if !isLegacyCliStdoutData(data) {
			continue
		}

		// Payload is raw stdout bytes (JSON for snyk test --json).
		payload, ok := data.GetPayload().([]byte)
		if !ok {
			continue
		}
		legacyResults, err := UnmarshallOssJson(payload)
		if err != nil {
			return nil, fmt.Errorf("couldn't unmarshal legacy json: %w", err)
		}
		for _, legacyResult := range legacyResults {
			targetFilePath := getAbsTargetFilePath(&logger, legacyResult.Path, legacyResult.DisplayTargetFile, workDir, filePath)
			fileContent := getFileContent(targetFilePath, readFiles, logger)
			issues = append(issues, convertScanResultToIssues(c, &legacyResult, workDir, targetFilePath, fileContent, learnService, errorReporter, packageIssueCache, format)...)
		}
	}
	return issues, nil
}
