/*
 * © 2022 Snyk Limited All rights reserved.
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

package iac

import (
	"context"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

// todo iac is undertested, at a very least we should make sure the CLI gets the right commands in
// todo test issue parsing & conversion

func defaultResolver(c *config.Config) types.ConfigResolverInterface {
	return testutil.DefaultConfigResolver(c)
}

// Test_Scan_UsesConfigResolverFromContext FC-067: IaC scanner uses resolver from context when available
func Test_Scan_UsesConfigResolverFromContext(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	c := testutil.UnitTest(t)
	mockResolver := mock_types.NewMockConfigResolverInterface(ctrl)
	mockResolver.EXPECT().
		IsProductEnabledForFolder(product.ProductInfrastructureAsCode, gomock.Any()).
		Return(false).
		Times(1)

	scanner := New(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(c), cli.NewTestExecutor(c), defaultResolver(c))
	folderConfig := &types.FolderConfig{FolderPath: "."}
	ctx := ctx2.NewContextWithConfigResolver(context.Background(), mockResolver)
	ctx = ctx2.NewContextWithFolderConfig(ctx, folderConfig)

	issues, err := scanner.Scan(ctx, "fake.yml")

	assert.NoError(t, err)
	assert.Empty(t, issues)
}

// Test_Scan_FallsBackToStructFieldWhenNoResolverInContext FC-064: IaC scanner falls back to struct field when context has no resolver
func Test_Scan_FallsBackToStructFieldWhenNoResolverInContext(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	c := testutil.UnitTest(t)
	mockResolver := mock_types.NewMockConfigResolverInterface(ctrl)
	mockResolver.EXPECT().
		IsProductEnabledForFolder(product.ProductInfrastructureAsCode, gomock.Any()).
		Return(false).
		Times(1)

	scanner := New(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(c), cli.NewTestExecutor(c), mockResolver)
	folderConfig := &types.FolderConfig{FolderPath: "."}
	ctx := ctx2.NewContextWithFolderConfig(context.Background(), folderConfig)

	issues, err := scanner.Scan(ctx, "fake.yml")

	assert.NoError(t, err)
	assert.Empty(t, issues)
}

func Test_Scan_IsInstrumented(t *testing.T) {
	c := testutil.UnitTest(t)
	instrumentor := performance.NewInstrumentor()
	scanner := New(c, instrumentor, error_reporting.NewTestErrorReporter(c), cli.NewTestExecutor(c), defaultResolver(c))
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), &types.FolderConfig{FolderPath: "."})

	_, _ = scanner.Scan(ctx, "fake.yml")

	if spanRecorder, ok := instrumentor.(performance.SpanRecorder); ok {
		spans := spanRecorder.Spans()
		assert.Len(t, spans, 1)
		assert.Equal(t, "iac.doScan", spans[0].GetOperation())
		assert.Equal(t, "", spans[0].GetTxName())
	} else {
		t.Fail()
	}
}

func Test_toHover_asHTML(t *testing.T) {
	c := testutil.UnitTest(t)
	scanner := New(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(c), cli.NewTestExecutor(c), defaultResolver(c))
	c.Engine().GetConfiguration().Set(configuration.UserGlobalKey(types.SettingFormat), config.FormatHtml)

	h := scanner.getExtendedMessage(sampleIssue())

	assert.Equal(
		t,
		"\n### PublicID: <p>Title</p>\n\n\n**Issue:** <p>Issue</p>\n\n\n**Impact:** <p>Impact</p>\n\n\n**Resolve:** <p>Resolve</p>\n\n",
		h,
	)
}

func Test_toHover_asMD(t *testing.T) {
	c := testutil.UnitTest(t)
	scanner := New(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(c), cli.NewTestExecutor(c), defaultResolver(c))
	c.Engine().GetConfiguration().Set(configuration.UserGlobalKey(types.SettingFormat), config.FormatMd)

	h := scanner.getExtendedMessage(sampleIssue())

	assert.Equal(
		t,
		"\n### PublicID: Title\n\n**Issue:** Issue\n\n**Impact:** Impact\n\n**Resolve:** Resolve\n",
		h,
	)
}

func Test_Scan_CancelledContext_DoesNotScan(t *testing.T) {
	// Arrange
	c := testutil.UnitTest(t)
	cliMock := cli.NewTestExecutor(c)
	scanner := New(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(c), cliMock, defaultResolver(c))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	ctx = ctx2.NewContextWithFolderConfig(ctx, &types.FolderConfig{FolderPath: "."})

	// Act
	_, _ = scanner.Scan(ctx, "")

	// Assert
	assert.False(t, cliMock.WasExecuted())
}

func Test_Scan_FileScan_UsesFolderConfigOrganization(t *testing.T) {
	c := testutil.UnitTest(t)

	// Setup - use real temp dirs
	workspaceDir := t.TempDir()
	workspacePath := types.FilePath(workspaceDir)

	// Create a subfolder with a terraform file
	subfolderPath := workspaceDir + "/infra/nested"
	assert.NoError(t, os.MkdirAll(subfolderPath, 0755))
	filePath := subfolderPath + "/main.tf"
	assert.NoError(t, os.WriteFile(filePath, []byte(`resource "aws_s3_bucket" "test" {}`), 0644))

	expectedOrg := "test-org-for-file-scan"
	engineConf := c.Engine().GetConfiguration()
	folderConfig := &types.FolderConfig{FolderPath: workspacePath}
	folderConfig.SetConf(engineConf)
	types.SetPreferredOrgAndOrgSetByUser(engineConf, workspacePath, expectedOrg, true)

	cliMock := cli.NewTestExecutor(c)
	scanner := New(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(c), cliMock, defaultResolver(c))

	// Act - scan a specific file within the workspace
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), folderConfig)
	_, _ = scanner.Scan(ctx, types.FilePath(filePath))

	// Assert - verify the CLI was executed with the correct org
	assert.True(t, cliMock.WasExecuted(), "CLI should be executed for file scan")
	assert.Contains(t, cliMock.GetCommand(), "--org="+expectedOrg, "CLI should be called with the org from folderConfig")
}

func Test_Scan_SubfolderScan_UsesFolderConfigOrganization(t *testing.T) {
	c := testutil.UnitTest(t)

	// Setup - use real temp dirs
	workspaceDir := t.TempDir()
	workspacePath := types.FilePath(workspaceDir)

	// Create a subfolder with a terraform file
	subfolderPath := workspaceDir + "/modules/subproject"
	assert.NoError(t, os.MkdirAll(subfolderPath, 0755))
	assert.NoError(t, os.WriteFile(subfolderPath+"/main.tf", []byte(`resource "aws_s3_bucket" "test" {}`), 0644))

	expectedOrg := "test-org-for-subfolder-scan"
	engineConf := c.Engine().GetConfiguration()
	folderConfig := &types.FolderConfig{FolderPath: workspacePath}
	folderConfig.SetConf(engineConf)
	types.SetPreferredOrgAndOrgSetByUser(engineConf, workspacePath, expectedOrg, true)

	cliMock := cli.NewTestExecutor(c)
	scanner := New(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(c), cliMock, defaultResolver(c))

	// Act - scan a subfolder (not the workspace root)
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), folderConfig)
	_, _ = scanner.Scan(ctx, types.FilePath(subfolderPath))

	// Assert - verify the CLI was executed with the correct org
	assert.True(t, cliMock.WasExecuted(), "CLI should be executed for subfolder scan")
	assert.Contains(t, cliMock.GetCommand(), "--org="+expectedOrg, "CLI should be called with the org from folderConfig")
}

func Test_Scan_UsesFolderConfigOrg(t *testing.T) {
	tests := []struct {
		name        string
		expectedOrg string
	}{
		{"WorkspaceFolderScan", "test-org-for-workspace-scan"},
		{"DeltaScanBaseBranch", "org-from-workspace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testutil.UnitTest(t)
			dir := t.TempDir()
			folderPath := types.FilePath(dir)
			assert.NoError(t, os.WriteFile(dir+"/main.tf", []byte(`resource "aws_s3_bucket" "test" {}`), 0644))

			engineConf := c.Engine().GetConfiguration()
			fc := &types.FolderConfig{FolderPath: folderPath}
			fc.SetConf(engineConf)
			types.SetPreferredOrgAndOrgSetByUser(engineConf, folderPath, tt.expectedOrg, true)

			cliMock := cli.NewTestExecutor(c)
			scanner := New(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(c), cliMock, defaultResolver(c))

			ctx := ctx2.NewContextWithFolderConfig(t.Context(), fc)
			_, _ = scanner.Scan(ctx, folderPath)

			assert.True(t, cliMock.WasExecuted(), "CLI should be executed")
			assert.Contains(t, cliMock.GetCommand(), "--org="+tt.expectedOrg)
		})
	}
}

// Test_Scan_UsesOrgFromFolderConfigNotFromPath verifies that the scanner uses the org from the
// passed FolderConfig parameter, not derived from the pathToScan path or global config.
// This is critical for delta scans where the scan path is a temp directory but the org
// should come from the original workspace's FolderConfig.
func Test_Scan_UsesOrgFromFolderConfigNotFromPath(t *testing.T) {
	c := testutil.UnitTest(t)

	// Setup three different orgs to ensure we're using the right one:
	// 1. Global default org - should NOT be used
	// 2. Org stored for the scan path - should NOT be used
	// 3. Org in the passed FolderConfig - SHOULD be used
	globalDefaultOrg := "global-default-org"
	orgStoredForPath := "org-stored-for-scan-path"
	expectedOrg := "org-from-passed-folderconfig"

	// Set global default org
	c.SetOrganization(globalDefaultOrg)

	// Create a directory that will be scanned
	scanDir := t.TempDir()
	scanPath := types.FilePath(scanDir)

	// Create a terraform file
	assert.NoError(t, os.WriteFile(scanDir+"/main.tf", []byte(`resource "aws_s3_bucket" "test" {}`), 0644))

	// Store a different org for the scan path (simulating a workspace with its own org)
	engineConf := c.Engine().GetConfiguration()
	types.SetPreferredOrgAndOrgSetByUser(engineConf, scanPath, orgStoredForPath, true)

	// Create the FolderConfig we'll pass to Scan() - with a DIFFERENT org
	// This simulates delta scan where we pass a config with the original workspace's org
	// Use a separate conf so the passed config has expectedOrg (not orgStoredForPath)
	passedConf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	types.SetPreferredOrgAndOrgSetByUser(passedConf, scanPath, expectedOrg, true)
	passedFolderConfig := &types.FolderConfig{FolderPath: scanPath}
	passedFolderConfig.SetConf(passedConf)

	cliMock := cli.NewTestExecutor(c)
	scanner := New(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(c), cliMock, defaultResolver(c))

	// Act
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), passedFolderConfig)
	_, _ = scanner.Scan(ctx, scanPath)

	// Assert - verify the CLI was called with the org from the PASSED FolderConfig,
	// not from the path's stored config or global default
	assert.True(t, cliMock.WasExecuted(), "CLI should be executed")
	cmd := cliMock.GetCommand()
	assert.Contains(t, cmd, "--org="+expectedOrg,
		"CLI should use org from passed FolderConfig, not from path lookup or global config")
	assert.NotContains(t, cmd, "--org="+orgStoredForPath,
		"CLI should NOT use org stored for the scan path")
	assert.NotContains(t, cmd, "--org="+globalDefaultOrg,
		"CLI should NOT use global default org")
}

func Test_retrieveIssues_IgnoresParsingErrors(t *testing.T) {
	c := testutil.UnitTest(t)

	scanner := New(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(c), cli.NewTestExecutor(c), defaultResolver(c))

	results := []iacScanResult{
		{
			ErrorCode: invalidJsonFileErrorCodeErrorCode,
		},
		{
			ErrorCode: failedToParseInputErrorCode,
		},
		{
			TargetFile: "fake.yml",
			IacIssues: []iacIssue{
				{
					PublicID: "test",
				},
			},
		},
	}
	issues, err := scanner.retrieveIssues(results, []types.Issue{}, "")

	assert.NoError(t, err)
	assert.Len(t, issues, 1)
}

func Test_createIssueDataForCustomUI_SuccessfullyParses(t *testing.T) {
	c := testutil.UnitTest(t)
	sampleIssue := sampleIssue()
	scanner := New(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(c), cli.NewTestExecutor(c), defaultResolver(c))
	issue, err := scanner.toIssue("/path/to/issue", "test.yml", sampleIssue, "")

	expectedAdditionalData := snyk.IaCIssueData{
		Key:      "6a4df51fc4d53f1cfbdb4b46c165859b",
		Title:    sampleIssue.Title,
		PublicId: sampleIssue.PublicID,
		// Documentation is a URL which is constructed from the PublicID
		Documentation: "https://security.snyk.io/rules/cloud/PublicID",
		LineNumber:    sampleIssue.LineNumber,
		Issue:         sampleIssue.IacDescription.Issue,
		Impact:        sampleIssue.IacDescription.Impact,
		Resolve:       sampleIssue.IacDescription.Resolve,
		References:    sampleIssue.References,
	}

	assert.NoError(t, err)
	assert.NotNil(t, issue.AdditionalData)

	actualAdditionalData, ok := issue.AdditionalData.(snyk.IaCIssueData)
	assert.True(t, ok)

	assert.Equal(t, expectedAdditionalData.Key, actualAdditionalData.Key)
	assert.Equal(t, expectedAdditionalData.Title, actualAdditionalData.Title)
	assert.Equal(t, expectedAdditionalData.PublicId, actualAdditionalData.PublicId)
	assert.Equal(t, expectedAdditionalData.Documentation, actualAdditionalData.Documentation)
	assert.Equal(t, expectedAdditionalData.LineNumber, actualAdditionalData.LineNumber)
	assert.Equal(t, expectedAdditionalData.Issue, actualAdditionalData.Issue)
	assert.Equal(t, expectedAdditionalData.Impact, actualAdditionalData.Impact)
	assert.Equal(t, expectedAdditionalData.Resolve, actualAdditionalData.Resolve)
	assert.Equal(t, expectedAdditionalData.References, actualAdditionalData.References)

	htmlRenderer, err := NewHtmlRenderer(c)
	assert.NoError(t, err)
	html := htmlRenderer.GetDetailsHtml(issue)

	assert.NotEmpty(t, html, "Details field should not be empty")
	assert.Contains(t, html, "<!DOCTYPE html>", "Details should contain HTML doctype declaration")
	assert.Contains(t, html, "PublicID", "Details should contain the PublicID")
}

func Test_toIssue_issueHasHtmlTemplate(t *testing.T) {
	c := testutil.UnitTest(t)
	sampleIssue := sampleIssue()
	scanner := New(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(c), cli.NewTestExecutor(c), defaultResolver(c))
	issue, err := scanner.toIssue("/path/to/issue", "test.yml", sampleIssue, "")

	assert.NoError(t, err)

	// Assert the Details field contains the HTML template and expected content
	htmlRenderer, err := NewHtmlRenderer(c)
	assert.NoError(t, err)
	html := htmlRenderer.GetDetailsHtml(issue)

	assert.NotEmpty(t, html, "HTML Details should not be empty")
	assert.Contains(t, html, "PublicID", "HTML should contain the PublicID")
}

func Test_getIssueId(t *testing.T) {
	affectedFilePath := types.FilePath("path/to/file/test.yml")
	id := getIssueKey(affectedFilePath, sampleIssue())

	assert.Equal(t, "4bd522a2fc6ce20c3258f9c194e0fca0", id)
}

func Test_parseIacIssuePath_SuccessfullyParses(t *testing.T) {
	testutil.UnitTest(t)
	// Unmarshall uses float64. From the docs:
	// To unmarshal JSON into an interface value,
	// Unmarshal stores one of these in the interface value:
	//
	//	bool, for JSON booleans
	//	float64, for JSON numbers
	//	string, for JSON strings
	//	[]interface{}, for JSON arrays
	//	map[string]interface{}, for JSON objects
	//	nil for JSON null
	rawPath := []any{"ingress", float32(32), "cidr_blocks", float64(64)}
	expectedPath := []string{"ingress", "32", "cidr_blocks", "64"}

	gotPath, gotErr := parseIacIssuePath(rawPath)

	assert.NoError(t, gotErr)
	assert.Equal(t, expectedPath, gotPath)
}

func Test_parseIacIssuePath_InvalidPathToken(t *testing.T) {
	testutil.UnitTest(t)
	rawPath := []any{"ingress", float64(0), "cidr_blocks", true}
	expectedErrorMessage := "unexpected type bool for IaC issue path token: true"

	gotPath, gotErr := parseIacIssuePath(rawPath)

	assert.Nil(t, gotPath)
	assert.EqualError(t, gotErr, expectedErrorMessage)
}

func Test_parseIacResult(t *testing.T) {
	c := testutil.UnitTest(t)
	testResult := "testdata/RBAC-iac-result.json"
	result, err := os.ReadFile(testResult)
	assert.NoError(t, err)
	scanner := Scanner{c: c, errorReporter: error_reporting.NewTestErrorReporter(c)}

	issues, err := scanner.unmarshal(result)
	assert.NoError(t, err)

	retrieveIssues, err := scanner.retrieveIssues(issues, []types.Issue{}, ".")
	assert.NoError(t, err)

	assert.Len(t, retrieveIssues, 2)
}

func Test_parseIacResult_failOnInvalidPath(t *testing.T) {
	c := testutil.UnitTest(t)
	testResult := "testdata/RBAC-iac-result-invalid-path.json"
	result, err := os.ReadFile(testResult)
	assert.NoError(t, err)
	scanner := Scanner{c: c, errorReporter: error_reporting.NewTestErrorReporter(c)}

	issues, err := scanner.unmarshal(result)
	assert.NoError(t, err)

	retrieveIssues, err := scanner.retrieveIssues(issues, []types.Issue{}, ".")
	assert.Error(t, err)

	assert.Len(t, retrieveIssues, 0)
}

func sampleIssue() iacIssue {
	return iacIssue{
		PublicID:      "PublicID",
		Title:         "Title",
		Severity:      "low",
		LineNumber:    3,
		Documentation: "4",
		IacDescription: iacDescription{
			Issue:   "Issue",
			Impact:  "Impact",
			Resolve: "Resolve",
		},
	}
}
