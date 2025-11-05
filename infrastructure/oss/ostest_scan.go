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
	"os"
	"strings"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/envvars"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/ast"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/product"
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
	gafConfig.Set(configuration.INPUT_DIRECTORY, []string{string(workDir)})
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
				// Enrich issues with quick-fix code actions and codelenses (unified path)
				issues = addUnifiedOssQuickFixesAndLenses(ctx, issues)
			}
		}
	}
	return issues, nil
}

// addUnifiedOssQuickFixesAndLenses attaches OSS quick-fix code actions and related codelenses
// to issues produced by the unified converter, reusing the legacy OSS machinery.
func addUnifiedOssQuickFixesAndLenses(ctx context.Context, issues []types.Issue) []types.Issue {
	if len(issues) == 0 {
		return issues
	}
	cfg := config.CurrentConfig()
	if !cfg.IsSnykOSSQuickFixCodeActionsEnabled() {
		return issues
	}

	learnService, errorReporter := resolveDependencies(ctx)
	enriched := make([]types.Issue, 0, len(issues))
	for _, it := range issues {
		enrichedIssue := enrichIssueWithCodeActions(it, learnService, errorReporter)
		enriched = append(enriched, enrichedIssue)
	}
	return enriched
}

// resolveDependencies extracts learn service and error reporter from context
func resolveDependencies(ctx context.Context) (learn.Service, error_reporting.ErrorReporter) {
	var learnService learn.Service
	var errorReporter error_reporting.ErrorReporter
	deps, ok := ctx2.DependenciesFromContext(ctx)
	if !ok {
		return learnService, errorReporter
	}
	if dep := deps[ctx2.DepLearnService]; dep != nil {
		if svc, ok := dep.(learn.Service); ok {
			learnService = svc
		}
	}
	if dep := deps[ctx2.DepErrorReporter]; dep != nil {
		if rep, ok := dep.(error_reporting.ErrorReporter); ok {
			errorReporter = rep
		}
	}
	return learnService, errorReporter
}

// enrichIssueWithCodeActions adds code actions and lenses to a single issue
func enrichIssueWithCodeActions(issue types.Issue, learnService learn.Service, errorReporter error_reporting.ErrorReporter) types.Issue {
	if issue.GetProduct() != product.ProductOpenSource {
		return issue
	}

	ossData, ok := issue.GetAdditionalData().(snyk.OssIssueData)
	if !ok {
		return issue
	}

	node := computeDependencyNode(issue, ossData)
	actions := AddCodeActionsFromOssIssueData(ossData, issue.GetID(), learnService, errorReporter, issue.GetAffectedFilePath(), node)
	if len(actions) == 0 {
		return issue
	}

	issue.SetCodeActions(actions)
	lenses := createCodeLensesFromActions(actions, issue.GetAffectedFilePath(), node)
	if len(lenses) > 0 {
		issue.SetCodelensCommands(lenses)
	}
	return issue
}

// computeDependencyNode finds the AST node for the dependency
func computeDependencyNode(issue types.Issue, ossData snyk.OssIssueData) *ast.Node {
	affected := issue.GetAffectedFilePath()
	depPath := ossData.From
	content, readErr := os.ReadFile(string(affected))
	if readErr != nil {
		config.CurrentConfig().Logger().Debug().Err(readErr).Str("file", string(affected)).Msg("cannot read file for quick-fix enrichment")
		return nil
	}
	l := config.CurrentConfig().Logger().With().Logger()
	return getDependencyNode(&l, affected, ossData.PackageManager, depPath, content)
}

// createCodeLensesFromActions creates code lens commands from upgrade code actions
func createCodeLensesFromActions(actions []types.CodeAction, affectedFilePath types.FilePath, node *ast.Node) []types.CommandData {
	var lenses []types.CommandData
	rangeFromNode := getRangeFromNode(node)
	for _, codeAction := range actions {
		if codeAction != nil && strings.Contains(codeAction.GetTitle(), "Upgrade to") {
			lenses = append(lenses, types.CommandData{
				Title:         codeAction.GetTitle(),
				CommandId:     types.CodeFixCommand,
				Arguments:     []any{codeAction.GetUuid(), affectedFilePath, rangeFromNode},
				GroupingKey:   codeAction.GetGroupingKey(),
				GroupingType:  codeAction.GetGroupingType(),
				GroupingValue: codeAction.GetGroupingValue(),
			})
		}
	}
	return lenses
}
