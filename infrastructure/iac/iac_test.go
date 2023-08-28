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
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/internal/testutil"
)

// todo iac is undertested, at a very least we should make sure the CLI gets the right commands in
// todo test issue parsing & conversion

func Test_Scan_IsInstrumented(t *testing.T) {
	testutil.UnitTest(t)
	instrumentor := performance.NewInstrumentor()
	scanner := New(instrumentor, error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics(), cli.NewTestExecutor())

	_, _ = scanner.Scan(context.Background(), "fake.yml", "")

	if spanRecorder, ok := instrumentor.(performance.SpanRecorder); ok {
		spans := spanRecorder.Spans()
		assert.Len(t, spans, 1)
		assert.Equal(t, "iac.doScan", spans[0].GetOperation())
		assert.Equal(t, "", spans[0].GetTxName())
	} else {
		t.Fail()
	}
}

func Test_SuccessfulScanFile_TracksAnalytics(t *testing.T) {
	testutil.UnitTest(t)
	analytics := ux2.NewTestAnalytics()
	scanner := New(performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), analytics, cli.NewTestExecutor())

	issues, err := scanner.Scan(context.Background(), "fake.yml", "")

	assert.Nil(t, err)
	assert.Len(t, issues, 0)
	assert.Len(t, analytics.GetAnalytics(), 1)
	assert.Equal(t, ux2.AnalysisIsReadyProperties{
		AnalysisType: ux2.InfrastructureAsCode,
		Result:       ux2.Success,
	}, analytics.GetAnalytics()[0])
}

func Test_ErroredWorkspaceScan_TracksAnalytics(t *testing.T) {
	testutil.UnitTest(t)
	analytics := ux2.NewTestAnalytics()
	executor := cli.NewTestExecutor()
	scanner := New(performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), analytics, executor)

	executor.ExecuteResponse = []byte("invalid JSON")
	issues, err := scanner.Scan(context.Background(), "fake.yml", "")

	assert.NotNil(t, err)
	assert.Len(t, issues, 0)
	assert.Len(t, analytics.GetAnalytics(), 1)
	assert.Equal(t, ux2.AnalysisIsReadyProperties{
		AnalysisType: ux2.InfrastructureAsCode,
		Result:       ux2.Error,
	}, analytics.GetAnalytics()[0])
}

func Test_toHover_asHTML(t *testing.T) {
	testutil.UnitTest(t)
	scanner := New(performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics(), cli.NewTestExecutor())
	config.CurrentConfig().SetFormat(config.FormatHtml)

	h := scanner.getExtendedMessage(sampleIssue())

	assert.Equal(
		t,
		"\n### PublicID: <p>Title</p>\n\n\n**Issue:** <p>Issue</p>\n\n\n**Impact:** <p>Impact</p>\n\n\n**Resolve:** <p>Resolve</p>\n\n",
		h,
	)
}

func Test_toHover_asMD(t *testing.T) {
	testutil.UnitTest(t)
	scanner := New(performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics(), cli.NewTestExecutor())
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
	testutil.UnitTest(t)
	cliMock := cli.NewTestExecutor()
	scanner := New(performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics(), cliMock)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Act
	_, _ = scanner.Scan(ctx, "", "")

	// Assert
	assert.False(t, cliMock.WasExecuted())
}

func Test_retrieveIssues_IgnoresParsingErrors(t *testing.T) {
	testutil.UnitTest(t)

	scanner := New(performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics(), cli.NewTestExecutor())

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
	issues, err := scanner.retrieveIssues(results, []snyk.Issue{}, "")

	assert.NoError(t, err)
	assert.Len(t, issues, 1)
}

func Test_createIssueDataForCustomUI_SuccessfullyParses(t *testing.T) {

	sampleIssue := sampleIssue()
	scanner := New(performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(), ux2.NewTestAnalytics(), cli.NewTestExecutor())
	issue, err := scanner.toIssue("test.yml", sampleIssue, "")

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
	assert.Equal(t, expectedAdditionalData, issue.AdditionalData)
}

func Test_getIssueId(t *testing.T) {

	affectedFilePath := "path/to/file/test.yml"
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
	testutil.UnitTest(t)
	testResult := "testdata/RBAC-iac-result.json"
	result, err := os.ReadFile(testResult)
	assert.NoError(t, err)
	scanner := Scanner{errorReporter: error_reporting.NewTestErrorReporter()}

	issues, err := scanner.unmarshal(result)
	assert.NoError(t, err)

	retrieveIssues, err := scanner.retrieveIssues(issues, []snyk.Issue{}, ".")
	assert.NoError(t, err)

	assert.Len(t, retrieveIssues, 2)
}

func Test_parseIacResult_failOnInvalidPath(t *testing.T) {
	testutil.UnitTest(t)
	testResult := "testdata/RBAC-iac-result-invalid-path.json"
	result, err := os.ReadFile(testResult)
	assert.NoError(t, err)
	scanner := Scanner{errorReporter: error_reporting.NewTestErrorReporter()}

	issues, err := scanner.unmarshal(result)
	assert.NoError(t, err)

	retrieveIssues, err := scanner.retrieveIssues(issues, []snyk.Issue{}, ".")
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
