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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
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
