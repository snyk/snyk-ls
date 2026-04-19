/*
 * © 2026 Snyk Limited
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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestVulnIndicesByID_GroupsIndicesInScanOrder(t *testing.T) {
	res := &scanResult{
		Vulnerabilities: []ossIssue{
			{Id: "A", PackageName: "p1"},
			{Id: "B", PackageName: "p2"},
			{Id: "A", PackageName: "p3"},
		},
	}
	got := vulnIndicesByID(res)
	require.Len(t, got, 2)
	assert.Equal(t, []int{0, 2}, got["A"])
	assert.Equal(t, []int{1}, got["B"])
}

func TestVulnIndicesByID_NilOrEmpty(t *testing.T) {
	assert.Nil(t, vulnIndicesByID(nil))
	assert.Nil(t, vulnIndicesByID(&scanResult{}))
}

func TestConvertScanResultToIssues_SameIdMultiplePackages_MatchingIssuesIncludesAllSameId(t *testing.T) {
	engine := testutil.UnitTest(t)
	issueID := "SNYK-DUP-1"
	scanResult := &scanResult{
		ProjectName: "test-project",
		Vulnerabilities: []ossIssue{
			{
				Id:             issueID,
				Name:           "n1",
				Title:          "t1",
				Severity:       "high",
				PackageName:    "pkg-a",
				Version:        "1.0.0",
				PackageManager: "npm",
				From:           []string{"lodash@4.17.4"},
			},
			{
				Id:             issueID,
				Name:           "n2",
				Title:          "t2",
				Severity:       "high",
				PackageName:    "pkg-b",
				Version:        "2.0.0",
				PackageManager: "npm",
				From:           []string{"lodash@4.17.4"},
			},
			{
				Id:             issueID,
				Name:           "n3",
				Title:          "t3",
				Severity:       "high",
				PackageName:    "pkg-c",
				Version:        "3.0.0",
				PackageManager: "npm",
				From:           []string{"lodash@4.17.4"},
			},
		},
	}

	workDir := types.FilePath("/test/workdir")
	targetFilePath := types.FilePath("/test/workdir/package.json")
	fileContent := []byte(`{"dependencies":{"lodash":"4.17.4"}}`)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	learnService := mock_learn.NewMockService(ctrl)
	learnService.EXPECT().
		GetLesson(gomock.Any(), issueID, gomock.Any(), gomock.Any(), types.DependencyVulnerability).
		Return(&learn.Lesson{Url: "https://learn.snyk.io/lesson/test"}, nil).
		AnyTimes()

	errorReporter := error_reporting.NewTestErrorReporter(engine)
	configResolver := testutil.DefaultConfigResolver(engine)

	issues := convertScanResultToIssues(engine, configResolver, scanResult, workDir, targetFilePath, fileContent, learnService, errorReporter, engine.GetConfiguration().GetString(configresolver.UserGlobalKey(types.SettingFormat)), nil)

	require.Len(t, issues, 3)
	for _, i := range issues {
		si, ok := i.(*snyk.Issue)
		require.True(t, ok)
		ad, ok := si.AdditionalData.(snyk.OssIssueData)
		require.True(t, ok)
		assert.Len(t, ad.MatchingIssueKeys, 3, "each issue should list keys for all three same-id vulns as matching")
	}
}
