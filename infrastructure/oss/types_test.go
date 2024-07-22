/*
 * © 2024 Snyk Limited
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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_ossIssueContainsPolicyAnnotations(t *testing.T) {
	testutil.UnitTest(t)

	issue := setupOssIssueWithPolicyAnnotations(t)

	require.NotEmpty(t, issue.AppliedPolicyRules.Annotation.Value)
	require.NotEmpty(t, issue.AppliedPolicyRules.Annotation.Reason)
}

func Test_ossIssue_toAdditionalData_ConvertsPolicyAnnotations(t *testing.T) {
	testutil.UnitTest(t)

	issue := setupOssIssueWithPolicyAnnotations(t)
	fakeScanResult := &scanResult{
		DisplayTargetFile: "testFile",
		ProjectName:       "test",
	}

	convertedIssue := issue.toAdditionalData(fakeScanResult, []snyk.OssIssueData{})

	require.NotEmpty(t, convertedIssue.AppliedPolicyRules.Annotation.Value)
	require.NotEmpty(t, convertedIssue.AppliedPolicyRules.Annotation.Reason)
}

func Test_ossIssue_toAdditionalData_ConvertsSeverityChange(t *testing.T) {
	testutil.UnitTest(t)
	issue := setupOssIssueWithSeverityChangePolicy(t)
	fakeScanResult := &scanResult{
		DisplayTargetFile: "testFile",
		ProjectName:       "test",
	}

	convertedIssue := issue.toAdditionalData(fakeScanResult, []snyk.OssIssueData{})

	require.NotEmpty(t, convertedIssue.AppliedPolicyRules.SeverityChange.OriginalSeverity)
	require.NotEmpty(t, convertedIssue.AppliedPolicyRules.SeverityChange.NewSeverity)
	require.NotEmpty(t, convertedIssue.AppliedPolicyRules.SeverityChange.Reason)
}

func Test_unmarshalGradleMultiProject(t *testing.T) {
	c := testutil.UnitTest(t)
	fileName := "gradle-multi-project.json"
	testDir := "testdata"
	file := filepath.Join(testDir, fileName)
	inputJson, err := os.ReadFile(file)
	require.NoError(t, err)

	var sc []scanResult
	err = json.Unmarshal(inputJson, &sc)
	require.NoError(t, err)

	assert.Len(t, sc, 4)

	scanner := NewCLIScanner(
		c,
		performance.NewInstrumentor(),
		error_reporting.NewTestErrorReporter(),
		cli.NewTestExecutor(),
		getLearnMock(t),
		notification.NewNotifier(),
	).(*CLIScanner)

	issues := scanner.unmarshallAndRetrieveAnalysis(context.Background(), inputJson, testDir, file)

	assert.Len(t, issues, 315)

	gradleRootCount := 0
	sampleAdminCount := 0
	sampleApiCount := 0
	sampleCommonCount := 0
	for _, issue := range issues {
		switch filepath.ToSlash(issue.AffectedFilePath) {
		case "/Users/bdoetsch/workspace/gradle-multi-module/build.gradle":
			gradleRootCount++
		case "/Users/bdoetsch/workspace/gradle-multi-module/sample-admin/build.gradle":
			sampleAdminCount++
		case "/Users/bdoetsch/workspace/gradle-multi-module/sample-api/build.gradle":
			sampleApiCount++
		case "/Users/bdoetsch/workspace/gradle-multi-module/sample-common/build.gradle":
			sampleCommonCount++
		default:
			require.FailNow(t, "Unexpected file path", issue.AffectedFilePath)
		}
	}

	assert.Equal(t, 135, sampleAdminCount)
	assert.Equal(t, 135, sampleApiCount)
	assert.Equal(t, 45, sampleCommonCount)
}

func setupOssIssueWithPolicyAnnotations(t *testing.T) ossIssue {
	t.Helper()
	name := filepath.Join("testdata", "policyAnnotationsInputData.json")
	issue := unmarshalIssueFromFile(t, name)
	return issue
}

func setupOssIssueWithSeverityChangePolicy(t *testing.T) ossIssue {
	t.Helper()
	name := filepath.Join("testdata", "policySeverityChangeInputData.json")
	issue := unmarshalIssueFromFile(t, name)
	return issue
}

func unmarshalIssueFromFile(t *testing.T, name string) ossIssue {
	t.Helper()
	inputJson, err := os.ReadFile(name)
	require.NoError(t, err)

	var issue ossIssue
	err = json.Unmarshal(inputJson, &issue)
	require.NoError(t, err)
	return issue
}
