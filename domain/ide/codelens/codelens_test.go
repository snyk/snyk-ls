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

package codelens

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/filter"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_GetCodeLensFromCommand(t *testing.T) {
	testutil.UnitTest(t)
	issue := code.FakeIssue
	command := code.FakeCommand
	codeLens := getCodeLensFromCommand(issue.Range, command)
	assert.Equal(t, converter.ToRange(issue.Range), codeLens.Range)
	assert.Equal(t, command.CommandId, codeLens.Command.Command)
	assert.Equal(t, command.Title, codeLens.Command.Title)
	assert.Equal(t, command.Arguments, codeLens.Command.Arguments)
}

func Test_GetCodeLensForPath(t *testing.T) {
	c := testutil.IntegTest(t)
	di.TestInit(t) // IntegTest doesn't automatically inits DI
	testutil.EnableSastAndAutoFix(c)
	// this is using the real progress channel, so we need to listen to it
	dummyProgressListeners(t)

	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true

	filePath, dir := code.TempWorkdirWithIssues(t)
	folder := workspace.NewFolder(c, dir, "dummy", di.Scanner(), di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator(), di.FeatureFlagService())
	c.Workspace().AddFolder(folder)

	// as code is only enabled if sast settings are enabled, and sast settings are checked in folder config
	// and sast settings are added in the `testutil.OnlyEnableCode` function, we need to call it after
	// adding the workspace folder
	testutil.OnlyEnableCode(t, c)

	folder.ScanFile(t.Context(), filePath)

	if folder.IssuesForFile(filePath) == nil {
		t.Fatal("issues for file should not be nil")
	}

	lenses := GetFor(filePath)

	if lenses == nil {
		t.Fatal("lenses should not be nil")
	}
	assert.Equal(t, 1, len(lenses))
	assert.Equal(t, lenses[0].Command.Title, code.FixIssuePrefix+code.DontUsePrintStackTrace)
}

func dummyProgressListeners(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { progress.CleanupChannels() })
	go func() {
		for {
			<-progress.ToServerProgressChannel
		}
	}()
}

func Test_filterIssuesForCodeLens_FiltersBySeverity(t *testing.T) {
	c := testutil.UnitTest(t)

	// Set severity filter to exclude Low
	severityFilter := types.NewSeverityFilter(true, true, true, false) // No Low
	c.SetSeverityFilter(&severityFilter)

	folderPath := types.FilePath("/test")

	issues := []types.Issue{
		&snyk.Issue{ID: "high-1", Severity: types.High, Range: types.Range{Start: types.Position{Line: 1}}},
		&snyk.Issue{ID: "high-2", Severity: types.High, Range: types.Range{Start: types.Position{Line: 1}}},
		&snyk.Issue{ID: "low-1", Severity: types.Low, Range: types.Range{Start: types.Position{Line: 1}}},
		&snyk.Issue{ID: "low-2", Severity: types.Low, Range: types.Range{Start: types.Position{Line: 1}}},
	}

	filtered := filter.FilterIssues(issues, c, folderPath)

	// Should only have High severity issues
	assert.Len(t, filtered, 2, "Should filter out Low severity issues")
	for _, issue := range filtered {
		assert.Equal(t, types.High, issue.GetSeverity(), "Filtered issues should only be High severity")
	}
}

func Test_filterIssuesForCodeLens_FiltersByRiskScore(t *testing.T) {
	c := testutil.UnitTest(t)

	folderPath := types.FilePath("/test")

	// Set risk score threshold
	riskThreshold := 500
	c.SetRiskScoreThreshold(&riskThreshold)

	// Enable risk score feature flag
	folderConfig := c.FolderConfig(folderPath)
	if folderConfig.FeatureFlags == nil {
		folderConfig.FeatureFlags = make(map[string]bool)
	}
	folderConfig.FeatureFlags[featureflag.UseExperimentalRiskScoreInCLI] = true
	err := c.UpdateFolderConfig(folderConfig)
	assert.NoError(t, err)

	issues := []types.Issue{
		&snyk.Issue{
			ID:             "high-risk-1",
			Severity:       types.High,
			Range:          types.Range{Start: types.Position{Line: 1}},
			AdditionalData: snyk.OssIssueData{RiskScore: 600},
		},
		&snyk.Issue{
			ID:             "high-risk-2",
			Severity:       types.High,
			Range:          types.Range{Start: types.Position{Line: 1}},
			AdditionalData: snyk.OssIssueData{RiskScore: 700},
		},
		&snyk.Issue{
			ID:             "low-risk-1",
			Severity:       types.High,
			Range:          types.Range{Start: types.Position{Line: 1}},
			AdditionalData: snyk.OssIssueData{RiskScore: 300},
		},
	}

	filtered := filter.FilterIssues(issues, c, folderPath)

	// Should only have issues with risk score >= 500
	assert.Len(t, filtered, 2, "Should filter out low risk score issue")
	for _, issue := range filtered {
		ossData := issue.GetAdditionalData().(snyk.OssIssueData)
		assert.GreaterOrEqual(t, int(ossData.RiskScore), 500, "Filtered issues should meet risk score threshold")
	}
}

func Test_filterIssuesForRange(t *testing.T) {
	testutil.UnitTest(t)

	targetRange := types.Range{
		Start: types.Position{Line: 10, Character: 0},
		End:   types.Position{Line: 10, Character: 10},
	}

	issues := []types.Issue{
		&snyk.Issue{ID: "in-range-1", Range: targetRange},
		&snyk.Issue{ID: "in-range-2", Range: targetRange},
		&snyk.Issue{ID: "out-of-range", Range: types.Range{Start: types.Position{Line: 20}}},
	}

	filtered := filterIssuesForRange(issues, targetRange)

	// Should only have issues in the target range
	assert.Len(t, filtered, 2, "Should filter to only issues in range")
	for _, issue := range filtered {
		assert.True(t, issue.GetRange().Overlaps(targetRange), "Filtered issues should overlap target range")
	}
}

func Test_GetFor_ShowsCodeLens_WhenAllIssuesAreFiltered(t *testing.T) {
	c := testutil.IntegTest(t)
	di.TestInit(t)
	testutil.EnableSastAndAutoFix(c)
	dummyProgressListeners(t)

	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true

	// Set severity filter to exclude all issues (no severities enabled)
	severityFilter := types.NewSeverityFilter(false, false, false, false)
	c.SetSeverityFilter(&severityFilter)

	filePath, dir := code.TempWorkdirWithIssues(t)
	folder := workspace.NewFolder(c, dir, "dummy", di.Scanner(), di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator(), di.FeatureFlagService())
	c.Workspace().AddFolder(folder)

	testutil.OnlyEnableCode(t, c)

	folder.ScanFile(t.Context(), filePath)

	if folder.IssuesForFile(filePath) == nil {
		t.Fatal("issues for file should not be nil")
	}

	// Get CodeLens - should still appear even though all issues are filtered by severity
	lenses := GetFor(filePath)

	// Should have CodeLens even though all issues are filtered
	assert.NotEmpty(t, lenses, "CodeLens should appear even when all issues are filtered")
}
