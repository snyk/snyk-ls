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
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/envvars"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/ast"
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

	// Resolve dependencies
	var ls learn.Service
	var er error_reporting.ErrorReporter
	if deps, ok := ctx2.DependenciesFromContext(ctx); ok {
		if dep := deps[ctx2.DepLearnService]; dep != nil {
			if svc, ok := dep.(learn.Service); ok {
				ls = svc
			}
		}
		if dep := deps[ctx2.DepErrorReporter]; dep != nil {
			if rep, ok := dep.(error_reporting.ErrorReporter); ok {
				er = rep
			}
		}
	}

	enriched := make([]types.Issue, 0, len(issues))
	for _, it := range issues {
		issue := it // copy for modification

		// Expect OSS additional data
		// Only handle issues that carry OSS additional data
		if issue.GetProduct() != product.ProductOpenSource {
			enriched = append(enriched, issue)
			continue
		}

		// We can type-assert directly to snyk.OssIssueData because this package can access it via the interface in domain
		// but since it's in another package, we rely on the concrete shape from types.IssueAdditionalData.
		// Use a type switch to extract fields if concrete type matches.
		var oi ossIssue

		// Extract via helper that understands OssIssueData
		if converted, ok := convertAdditionalDataToOssIssue(it.GetAdditionalData()); ok {
			oi = converted
		} else {
			enriched = append(enriched, issue)
			continue
		}

		// compute dependency node for accurate range/code fix
		affected := issue.GetAffectedFilePath()
		depPath := oi.From
		content, readErr := os.ReadFile(string(affected))
		if readErr != nil {
			cfg.Logger().Debug().Err(readErr).Str("file", string(affected)).Msg("cannot read file for quick-fix enrichment")
		}
		var node *ast.Node
		if readErr == nil {
			l := cfg.Logger().With().Logger()
			node = getDependencyNode(&l, affected, oi.PackageManager, depPath, content)
		}

		// add actions and derive lenses
		actions := oi.AddCodeActions(ls, er, affected, node)
		if len(actions) > 0 {
			issue.SetCodeActions(actions)
			var lenses []types.CommandData
			rangeFromNode := getRangeFromNode(node)
			for _, ca := range actions {
				if ca != nil && strings.Contains(ca.GetTitle(), "Upgrade to") {
					lenses = append(lenses, types.CommandData{
						Title:         ca.GetTitle(),
						CommandId:     types.CodeFixCommand,
						Arguments:     []any{ca.GetUuid(), affected, rangeFromNode},
						GroupingKey:   ca.GetGroupingKey(),
						GroupingType:  ca.GetGroupingType(),
						GroupingValue: ca.GetGroupingValue(),
					})
				}
			}
			if len(lenses) > 0 {
				issue.SetCodelensCommands(lenses)
			}
		}

		enriched = append(enriched, issue)
	}
	return enriched
}

// convertAdditionalDataToOssIssue maps AdditionalData (OssIssueData) back to a minimal ossIssue
// to reuse legacy quick-fix generation.
func convertAdditionalDataToOssIssue(additional any) (ossIssue, bool) {
	// We rely on json tags/field names of snyk.OssIssueData via type assertions by field accessors
	// Since OssIssueData is defined in another package, use reflection-less safe cast via known interface.
	type ossLike struct {
		Title          string   `json:"title"`
		Name           string   `json:"name"`
		PackageManager string   `json:"packageManager"`
		PackageName    string   `json:"packageName"`
		From           []string `json:"from"`
		UpgradePath    []any    `json:"upgradePath"`
		FixedIn        []string `json:"fixedIn"`
		IsUpgradable   bool     `json:"isUpgradable"`
		Language       string   `json:"language"`
		Id             string   `json:"id"`
	}
	b, err := jsonMarshal(additional)
	if err != nil {
		return ossIssue{}, false
	}
	var tmp ossLike
	if err := jsonUnmarshal(b, &tmp); err != nil {
		return ossIssue{}, false
	}
	oi := ossIssue{
		Id:             tmp.Id,
		Title:          tmp.Title,
		Name:           tmp.Name,
		PackageManager: tmp.PackageManager,
		PackageName:    tmp.PackageName,
		From:           tmp.From,
		UpgradePath:    tmp.UpgradePath,
		FixedIn:        tmp.FixedIn,
		IsUpgradable:   tmp.IsUpgradable,
		Language:       tmp.Language,
	}
	return oi, true
}

// small wrappers to avoid importing encoding/json at top if not present yet
func jsonMarshal(v any) ([]byte, error)   { return json.Marshal(v) }
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
