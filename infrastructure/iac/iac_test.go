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

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// todo iac is undertested, at a very least we should make sure the CLI gets the right commands in
// todo test issue parsing & conversion

func Test_Scan_IsInstrumented(t *testing.T) {
	c := testutil.UnitTest(t)
	instrumentor := performance.NewInstrumentor()
	scanner := New(c, instrumentor, error_reporting.NewTestErrorReporter(), cli.NewTestExecutor())

	_, _ = scanner.Scan(context.Background(), "fake.yml", "", nil)

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
	scanner := New(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), cli.NewTestExecutor())
	config.CurrentConfig().SetFormat(config.FormatHtml)

	h := scanner.getExtendedMessage(sampleIssue())

	assert.Equal(
		t,
		"\n### PublicID: <p>Title</p>\n\n\n**Issue:** <p>Issue</p>\n\n\n**Impact:** <p>Impact</p>\n\n\n**Resolve:** <p>Resolve</p>\n\n",
		h,
	)
}

func Test_toHover_asMD(t *testing.T) {
	c := testutil.UnitTest(t)
	scanner := New(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), cli.NewTestExecutor())
	config.CurrentConfig().SetFormat(config.FormatMd)

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
	cliMock := cli.NewTestExecutor()
	scanner := New(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), cliMock)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Act
	_, _ = scanner.Scan(ctx, "", "", nil)

	// Assert
	assert.False(t, cliMock.WasExecuted())
}

func Test_retrieveIssues_IgnoresParsingErrors(t *testing.T) {
	c := testutil.UnitTest(t)

	scanner := New(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), cli.NewTestExecutor())

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
	scanner := New(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), cli.NewTestExecutor())
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
	scanner := New(c, performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), cli.NewTestExecutor())
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
	scanner := Scanner{c: c, errorReporter: error_reporting.NewTestErrorReporter()}

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
	scanner := Scanner{c: c, errorReporter: error_reporting.NewTestErrorReporter()}

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
