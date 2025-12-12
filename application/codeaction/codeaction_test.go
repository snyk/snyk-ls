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

package codeaction_test

import (
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/codeaction"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/watcher"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/mock_snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

var exampleRange = sglsp.Range{
	Start: sglsp.Position{
		Line:      10,
		Character: 0,
	},
	End: sglsp.Position{
		Line:      10,
		Character: 8,
	},
}

const documentUriExample = sglsp.DocumentURI("file:///path/to/file")

func Test_GetCodeActions_ReturnsCorrectActions(t *testing.T) {
	c := testutil.UnitTest(t)
	expectedIssue := &snyk.Issue{
		CodeActions: []types.CodeAction{
			&snyk.CodeAction{
				Title:         "Fix this",
				OriginalTitle: "Fix this",
				Command:       &code.FakeCommand,
			},
		},
	}
	service, codeActionsParam, _ := setupWithSingleIssue(t, c, expectedIssue)

	// Act
	actions := service.GetCodeActions(codeActionsParam)

	// Assert
	assert.Len(t, actions, 1)
	assert.Equal(t, expectedIssue.CodeActions[0].GetCommand().CommandId, actions[0].Command.Command)
}

func Test_GetCodeActions_FileIsDirty_ReturnsEmptyResults(t *testing.T) {
	c := testutil.UnitTest(t)
	fakeIssue := &snyk.Issue{
		CodeActions: []types.CodeAction{
			&snyk.CodeAction{
				Title:         "Fix this",
				OriginalTitle: "Fix this",
				Command:       &code.FakeCommand,
			},
		},
	}
	service, codeActionsParam, w := setupWithSingleIssue(t, c, fakeIssue)
	w.SetFileAsChanged(codeActionsParam.TextDocument.URI) // File is dirty until it is saved

	// Act
	actions := service.GetCodeActions(codeActionsParam)

	// Assert
	assert.Empty(t, actions)
}

func Test_GetCodeActions_NoIssues_ReturnsNil(t *testing.T) {
	c := testutil.UnitTest(t)
	// It doesn't seem like there's a difference between returning a nil and returning an empty array. If this assumption
	// is proved to be false, this test can be changed.
	// Arrange
	// Set up workspace with folder that contains the test file path
	// The document URI is "file:///path/to/file", so the folder should be "/path/to"
	_, _ = workspaceutil.SetupWorkspace(t, c, types.FilePath("/path/to"))

	ctrl := gomock.NewController(t)
	var issues []types.Issue
	providerMock := mock_snyk.NewMockIssueProvider(ctrl)
	providerMock.EXPECT().IssuesForRange(gomock.Any(), gomock.Any()).Return(issues)
	service := codeaction.NewService(c, providerMock, watcher.NewFileWatcher(), notification.NewMockNotifier(), featureflag.NewFakeService())
	codeActionsParam := types.CodeActionParams{
		TextDocument: sglsp.TextDocumentIdentifier{
			URI: documentUriExample,
		},
		Range:   exampleRange,
		Context: types.CodeActionContext{},
	}

	// Act
	actions := service.GetCodeActions(codeActionsParam)

	// Assert
	assert.Nil(t, actions)
}

func Test_ResolveCodeAction_ReturnsCorrectEdit(t *testing.T) {
	c := testutil.UnitTest(t)
	// Arrange

	mockTextEdit := types.TextEdit{
		Range: types.Range{
			Start: types.Position{Line: 1, Character: 2},
			End:   types.Position{Line: 3, Character: 4},
		},
		NewText: "someText",
	}
	mockEdit := &types.WorkspaceEdit{
		Changes: map[string][]types.TextEdit{
			"someUri": {mockTextEdit},
		},
	}
	deferredEdit := func() *types.WorkspaceEdit {
		return mockEdit
	}
	id := uuid.New()
	expectedIssue := &snyk.Issue{
		CodeActions: []types.CodeAction{
			&snyk.CodeAction{
				Title:         "Fix this",
				OriginalTitle: "Fix this",
				DeferredEdit:  &deferredEdit,
				Uuid:          &id,
			},
		},
	}
	service, codeActionsParam, _ := setupWithSingleIssue(t, c, expectedIssue)

	// Act
	actions := service.GetCodeActions(codeActionsParam)
	actionFromRequest := actions[0]
	resolvedAction, _ := service.ResolveCodeAction(actionFromRequest)

	// Assert
	assert.NotNil(t, resolvedAction)
	assert.Equal(t, types.CodeActionData(id), *resolvedAction.Data)
	assert.Nil(t, actionFromRequest.Edit)
	assert.Nil(t, actionFromRequest.Command)
	assert.NotNil(t, resolvedAction.Edit)
}

func Test_ResolveCodeAction_KeyDoesNotExist_ReturnError(t *testing.T) {
	c := testutil.UnitTest(t)
	// Arrange
	service := setupService(t, c)

	id := types.CodeActionData(uuid.New())
	ca := types.LSPCodeAction{
		Title:   "Made up CA",
		Edit:    nil,
		Command: nil,
		Data:    &id,
	}

	// Act
	var err error
	_, err = service.ResolveCodeAction(ca)

	// Assert
	assert.Error(t, err, "Expected error when resolving a code action with a key that doesn't exist")
}

func Test_ResolveCodeAction_KeyAndCommandIsNull_ReturnsError(t *testing.T) {
	c := testutil.UnitTest(t)
	service := setupService(t, c)

	ca := types.LSPCodeAction{
		Title:   "Made up CA",
		Edit:    nil,
		Command: nil,
		Data:    nil,
	}

	_, err := service.ResolveCodeAction(ca)
	assert.Error(t, err, "Expected error when resolving a code action with a null key")
	assert.True(t, codeaction.IsMissingKeyError(err))
}

func Test_ResolveCodeAction_KeyIsNull_ReturnsCodeAction(t *testing.T) {
	c := testutil.UnitTest(t)
	service := setupService(t, c)

	expected := types.LSPCodeAction{
		Title:   "Made up CA",
		Edit:    nil,
		Command: &sglsp.Command{Command: "test"},
		Data:    nil,
	}

	actual, err := service.ResolveCodeAction(expected)
	assert.NoError(t, err, "Expected error when resolving a code action with a null key")
	assert.Equal(t, expected.Command.Command, actual.Command.Command)
}

func Test_UpdateIssuesWithQuickFix_TitleConcatenationIssue_WhenCalledMultipleTimes(t *testing.T) {
	c := testutil.UnitTest(t)
	service := setupService(t, c)

	quickFix := &snyk.CodeAction{
		Title:         "Upgrade to logback-core:1.3.15",
		OriginalTitle: "Upgrade to logback-core:1.3.15",
		GroupingType:  types.Quickfix,
	}

	quickFixGroupables := []types.Groupable{quickFix}

	// Helper to create fresh issues for each call
	createIssues := func() []types.Issue {
		return []types.Issue{
			&snyk.Issue{CodeActions: []types.CodeAction{quickFix}},
			&snyk.Issue{CodeActions: []types.CodeAction{}},
			&snyk.Issue{CodeActions: []types.CodeAction{}},
			&snyk.Issue{CodeActions: []types.CodeAction{}},
			&snyk.Issue{CodeActions: []types.CodeAction{}},
		}
	}

	// Test with same filtered and all issues (no filtering scenario)
	// Since no filtering, should only show ONE action without "displayed"
	issues1 := createIssues()
	updatedIssues1 := service.UpdateIssuesWithQuickFixes(quickFixGroupables, quickFixGroupables, issues1, issues1)

	// Check the title in the returned issues (not the original quickFix)
	// Should say "fix 1 issue" not "fix 1 displayed issue" since no filtering
	expectedTitle := "Upgrade to logback-core:1.3.15 and fix 1 issue (4 unfixable)"
	assert.Greater(t, len(updatedIssues1), 0, "Should have updated issues")
	if len(updatedIssues1) > 0 {
		actions := updatedIssues1[0].GetCodeActions()
		assert.Len(t, actions, 1, "Should have exactly 1 action when no filtering")
		if len(actions) > 0 {
			assert.Equal(t, expectedTitle, actions[0].GetTitle(),
				"First call should have correct title without 'displayed'")
			assert.NotContains(t, actions[0].GetTitle(), "displayed",
				"Should not contain 'displayed' when no filtering active")
		}
	}

	// Second call with fresh issues - the title should be correctly formatted again (not concatenated)
	issues2 := createIssues()
	updatedIssues2 := service.UpdateIssuesWithQuickFixes(quickFixGroupables, quickFixGroupables, issues2, issues2)

	assert.Greater(t, len(updatedIssues2), 0, "Should have updated issues")
	if len(updatedIssues2) > 0 {
		actions := updatedIssues2[0].GetCodeActions()
		assert.Len(t, actions, 1, "Should have exactly 1 action when no filtering")
		if len(actions) > 0 {
			assert.Equal(t, expectedTitle, actions[0].GetTitle(),
				"Second call should have same correct title, not concatenated. Expected: %s, Got: %s",
				expectedTitle, actions[0].GetTitle())
		}
	}

	// Third call with fresh issues - title should still be correct (not concatenated three times)
	issues3 := createIssues()
	updatedIssues3 := service.UpdateIssuesWithQuickFixes(quickFixGroupables, quickFixGroupables, issues3, issues3)

	assert.Greater(t, len(updatedIssues3), 0, "Should have updated issues")
	if len(updatedIssues3) > 0 {
		actions := updatedIssues3[0].GetCodeActions()
		assert.Len(t, actions, 1, "Should have exactly 1 action when no filtering")
		if len(actions) > 0 {
			assert.Equal(t, expectedTitle, actions[0].GetTitle(),
				"Third call should have same correct title, not concatenated. Expected: %s, Got: %s",
				expectedTitle, actions[0].GetTitle())

			// Additional assertion: verify that titles are not growing
			originalTitleLength := len("Upgrade to logback-core:1.3.15")
			assert.False(t, len(actions[0].GetTitle()) > originalTitleLength+60,
				"Title should not grow significantly. Original length: %d, Current length: %d",
				originalTitleLength, len(actions[0].GetTitle()))
		}
	}
}

func setupService(t *testing.T, c *config.Config) *codeaction.CodeActionsService {
	t.Helper()
	// Set up workspace with folder that contains the test file path
	// The document URI is "file:///path/to/file", so the folder should be "/path/to"
	_, _ = workspaceutil.SetupWorkspace(t, c, types.FilePath("/path/to"))

	providerMock := mock_snyk.NewMockIssueProvider(gomock.NewController(t))
	providerMock.EXPECT().IssuesForRange(gomock.Any(), gomock.Any()).Return([]types.Issue{}).AnyTimes()
	service := codeaction.NewService(c, providerMock, watcher.NewFileWatcher(), notification.NewMockNotifier(), featureflag.NewFakeService())
	return service
}

func Test_GetCodeActions_FiltersBySeverity_ExcludesLowSeverity(t *testing.T) {
	c := testutil.UnitTest(t)

	// Create issues with different severities
	highSeverityIssue := createOssIssueWithSeverityAndQuickFix(t, types.High, "high-vuln", "1.0.0")
	lowSeverityIssue := createOssIssueWithSeverityAndQuickFix(t, types.Low, "low-vuln", "1.0.0")

	// Set severity filter to exclude Low severity
	severityFilter := types.NewSeverityFilter(true, true, true, false) // Critical, High, Medium, no Low
	c.SetSeverityFilter(&severityFilter)

	service, codeActionsParam := setupWithMultipleIssues(t, c, []types.Issue{highSeverityIssue, lowSeverityIssue})

	// Act
	actions := service.GetCodeActions(codeActionsParam)

	// Assert - should have TWO quickfix actions (displayed and all)
	quickFixActions := findAllQuickFixActions(actions)
	assert.Len(t, quickFixActions, 2, "Should have both displayed and all issue actions")

	// Find the displayed issues action
	var displayedAction *types.LSPCodeAction
	for i := range quickFixActions {
		if strings.Contains(quickFixActions[i].Title, "displayed") {
			displayedAction = &quickFixActions[i]
			break
		}
	}

	// The displayed action should count only the High severity issue (1)
	assert.NotNil(t, displayedAction, "Should have a displayed issues action")
	if displayedAction != nil {
		assert.Contains(t, displayedAction.Title, "fix 1 displayed issue", "Should only count the High severity issue, not the filtered-out Low issue")
	}
}

func Test_GetCodeActions_FiltersByRiskScore_ExcludesLowRiskScore(t *testing.T) {
	c := testutil.UnitTest(t)

	// Enable risk score feature flag in folder config
	folderPath := types.FilePath("/path/to")
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPath)

	// Get the folder config and set the feature flag
	folderConfig := c.FolderConfig(folderPath)
	if folderConfig.FeatureFlags == nil {
		folderConfig.FeatureFlags = make(map[string]bool)
	}
	folderConfig.FeatureFlags[featureflag.UseExperimentalRiskScoreInCLI] = true
	err := c.UpdateFolderConfig(folderConfig)
	assert.NoError(t, err, "Failed to update folder config")

	ffs := featureflag.NewFakeService()
	ffs.Flags[featureflag.UseExperimentalRiskScoreInCLI] = true

	// Set risk score threshold to 500
	riskThreshold := 500
	c.SetRiskScoreThreshold(&riskThreshold)

	// Create issues with different risk scores
	highRiskIssue := createOssIssueWithRiskScoreAndQuickFix(t, 600, "high-risk-vuln", "1.0.0")
	lowRiskIssue := createOssIssueWithRiskScoreAndQuickFix(t, 300, "low-risk-vuln", "1.0.0")

	service, codeActionsParam := setupWithMultipleIssuesAndFeatureFlags(t, c, []types.Issue{highRiskIssue, lowRiskIssue}, ffs)

	// Act
	actions := service.GetCodeActions(codeActionsParam)

	// Assert - should have TWO quickfix actions (displayed and all)
	quickFixActions := findAllQuickFixActions(actions)
	assert.Len(t, quickFixActions, 2, "Should have both displayed and all issue actions")

	// Find the displayed issues action
	var displayedAction *types.LSPCodeAction
	for i := range quickFixActions {
		if strings.Contains(quickFixActions[i].Title, "displayed") {
			displayedAction = &quickFixActions[i]
			break
		}
	}

	// The displayed action should count only the high risk score issue (1)
	assert.NotNil(t, displayedAction, "Should have a displayed issues action")
	if displayedAction != nil {
		assert.Contains(t, displayedAction.Title, "fix 1 displayed issue", "Should only count the high risk score issue, not the filtered-out low risk issue")
	}
}

func Test_GetCodeActions_QuickFixTitle_ReflectsFilteredIssueCount(t *testing.T) {
	c := testutil.UnitTest(t)

	// Set severity filter to exclude Low severity
	severityFilter := types.NewSeverityFilter(true, true, true, false) // No Low
	c.SetSeverityFilter(&severityFilter)

	// Create 3 high severity issues and 2 low severity issues, all fixable by same upgrade
	issues := []types.Issue{
		createOssIssueWithSeverityAndQuickFix(t, types.High, "vuln-1", "2.0.0"),
		createOssIssueWithSeverityAndQuickFix(t, types.High, "vuln-2", "2.0.0"),
		createOssIssueWithSeverityAndQuickFix(t, types.High, "vuln-3", "2.0.0"),
		createOssIssueWithSeverityAndQuickFix(t, types.Low, "vuln-4", "2.0.0"),
		createOssIssueWithSeverityAndQuickFix(t, types.Low, "vuln-5", "2.0.0"),
	}

	service, codeActionsParam := setupWithMultipleIssues(t, c, issues)

	// Act
	actions := service.GetCodeActions(codeActionsParam)

	// Assert - should have both displayed and all issue actions
	quickFixActions := findAllQuickFixActions(actions)
	assert.Len(t, quickFixActions, 2, "Should have both displayed and all issue actions")

	// Find both actions
	var displayedAction, allAction *types.LSPCodeAction
	for i := range quickFixActions {
		if strings.Contains(quickFixActions[i].Title, "displayed") {
			displayedAction = &quickFixActions[i]
		} else {
			// The action without "displayed" is the all-issues action
			allAction = &quickFixActions[i]
		}
	}

	// Assert displayed action counts only filtered issues (3)
	assert.NotNil(t, displayedAction, "Should have a displayed issues action")
	if displayedAction != nil {
		assert.Contains(t, displayedAction.Title, "fix 3 displayed issues",
			"Displayed action should only count filtered (High severity) issues. Got: %s", displayedAction.Title)
	}

	// Assert all action counts all issues (5)
	assert.NotNil(t, allAction, "Should have an all issues action")
	if allAction != nil {
		assert.Contains(t, allAction.Title, "fix 5 issues",
			"All action should count all issues. Got: %s", allAction.Title)
	}
}

func Test_GetCodeActions_QuickFixUnfixableCount_ReflectsFilteredIssues(t *testing.T) {
	c := testutil.UnitTest(t)

	// Set severity filter to exclude Low severity
	severityFilter := types.NewSeverityFilter(true, true, true, false) // No Low
	c.SetSeverityFilter(&severityFilter)

	// Create 2 fixable high severity issues and 3 unfixable (1 high, 2 low)
	issues := []types.Issue{
		createOssIssueWithSeverityAndQuickFix(t, types.High, "vuln-1", "2.0.0"),
		createOssIssueWithSeverityAndQuickFix(t, types.High, "vuln-2", "2.0.0"),
		createOssIssueWithSeverity(t, types.High, "unfixable-high"), // unfixable high
		createOssIssueWithSeverity(t, types.Low, "unfixable-low-1"), // unfixable low
		createOssIssueWithSeverity(t, types.Low, "unfixable-low-2"), // unfixable low
	}

	service, codeActionsParam := setupWithMultipleIssues(t, c, issues)

	// Act
	actions := service.GetCodeActions(codeActionsParam)

	// Assert - should have both displayed and all issue actions
	quickFixActions := findAllQuickFixActions(actions)
	assert.Len(t, quickFixActions, 2, "Should have both displayed and all issue actions")

	// Find both actions
	var displayedAction, allAction *types.LSPCodeAction
	for i := range quickFixActions {
		if strings.Contains(quickFixActions[i].Title, "displayed") {
			displayedAction = &quickFixActions[i]
		} else {
			// The action without "displayed" is the all-issues action
			allAction = &quickFixActions[i]
		}
	}

	// Displayed action should show "fix 2 displayed issues (1 unfixable)" counting only High severity
	assert.NotNil(t, displayedAction, "Should have a displayed issues action")
	if displayedAction != nil {
		assert.Contains(t, displayedAction.Title, "(1 unfixable)",
			"Should only count unfixable High severity issues, not Low. Got: %s", displayedAction.Title)
		assert.Contains(t, displayedAction.Title, "fix 2 displayed issues",
			"Should show 2 fixable displayed issues. Got: %s", displayedAction.Title)
	}

	// All action should show "fix 2 issues (3 unfixable)" counting all issues
	assert.NotNil(t, allAction, "Should have an all issues action")
	if allAction != nil {
		assert.Contains(t, allAction.Title, "(3 unfixable)",
			"Should count all unfixable issues. Got: %s", allAction.Title)
		assert.Contains(t, allAction.Title, "fix 2 issues",
			"Should show 2 fixable issues total. Got: %s", allAction.Title)
	}
}

// Helper functions for tests

func createOssIssueWithSeverityAndQuickFix(t *testing.T, severity types.Severity, vulnId string, fixVersion string) types.Issue {
	t.Helper()
	quickFixAction := createQuickFixAction(t, fixVersion)

	return &snyk.Issue{
		ID:               vulnId,
		Severity:         severity,
		AffectedFilePath: uri.PathFromUri(documentUriExample),
		Range:            converter.FromRange(exampleRange),
		CodeActions:      []types.CodeAction{quickFixAction},
		AdditionalData: snyk.OssIssueData{
			Key:         vulnId,
			PackageName: "test-package",
			UpgradePath: []any{"test-package@" + fixVersion},
			RiskScore:   500, // Default risk score
		},
	}
}

func createOssIssueWithRiskScoreAndQuickFix(t *testing.T, riskScore uint16, vulnId string, fixVersion string) types.Issue {
	t.Helper()
	issue := createOssIssueWithSeverityAndQuickFix(t, types.High, vulnId, fixVersion)
	ossData := issue.GetAdditionalData().(snyk.OssIssueData)
	ossData.RiskScore = riskScore
	issue.(*snyk.Issue).AdditionalData = ossData
	return issue
}

func createOssIssueWithSeverity(t *testing.T, severity types.Severity, vulnId string) types.Issue {
	t.Helper()
	return &snyk.Issue{
		ID:               vulnId,
		Severity:         severity,
		AffectedFilePath: uri.PathFromUri(documentUriExample),
		Range:            converter.FromRange(exampleRange),
		CodeActions:      []types.CodeAction{}, // No quickfix - unfixable
		AdditionalData: snyk.OssIssueData{
			Key:         vulnId,
			PackageName: "test-package",
			RiskScore:   500,
		},
	}
}

func createQuickFixAction(t *testing.T, fixVersion string) types.CodeAction {
	t.Helper()
	id := uuid.New()
	return &snyk.CodeAction{
		Title:         "⚡️ Upgrade to " + fixVersion,
		OriginalTitle: "⚡️ Upgrade to " + fixVersion,
		Uuid:          &id,
		GroupingType:  types.Quickfix,
		GroupingKey:   types.Key("test-package"),
		GroupingValue: fixVersion,
	}
}

func findAllQuickFixActions(actions []types.LSPCodeAction) []types.LSPCodeAction {
	var quickFixActions []types.LSPCodeAction
	for i := range actions {
		if actions[i].Title == "" {
			continue
		}
		// Check if it's a quickfix (contains "Upgrade" or the lightning emoji symbol)
		if strings.Contains(actions[i].Title, "Upgrade") || strings.Contains(actions[i].Title, "⚡") {
			quickFixActions = append(quickFixActions, actions[i])
		}
	}
	return quickFixActions
}

func setupWithMultipleIssues(t *testing.T, c *config.Config, issues []types.Issue) (*codeaction.CodeActionsService, types.CodeActionParams) {
	t.Helper()
	folderPath := types.FilePath("/path/to")
	_, _ = workspaceutil.SetupWorkspace(t, c, folderPath)
	return setupWithMultipleIssuesAndFeatureFlags(t, c, issues, featureflag.NewFakeService())
}

func setupWithMultipleIssuesAndFeatureFlags(t *testing.T, c *config.Config, issues []types.Issue, ffs featureflag.Service) (*codeaction.CodeActionsService, types.CodeActionParams) {
	t.Helper()
	r := exampleRange
	uriPath := documentUriExample
	path := uri.PathFromUri(uriPath)

	providerMock := mock_snyk.NewMockIssueProvider(gomock.NewController(t))
	providerMock.EXPECT().IssuesForRange(path, converter.FromRange(r)).Return(issues).AnyTimes()
	fileWatcher := watcher.NewFileWatcher()
	service := codeaction.NewService(c, providerMock, fileWatcher, notification.NewMockNotifier(), ffs)

	codeActionsParam := types.CodeActionParams{
		TextDocument: sglsp.TextDocumentIdentifier{
			URI: uriPath,
		},
		Range:   r,
		Context: types.CodeActionContext{},
	}
	return service, codeActionsParam
}

func setupWithSingleIssue(t *testing.T, c *config.Config, issue types.Issue) (*codeaction.CodeActionsService, types.CodeActionParams, *watcher.FileWatcher) {
	t.Helper()
	r := exampleRange
	uriPath := documentUriExample
	path := uri.PathFromUri(uriPath)

	// Set up workspace with folder that contains the test file path
	// The document URI is "file:///path/to/file", so the folder should be "/path/to"
	_, _ = workspaceutil.SetupWorkspace(t, c, types.FilePath("/path/to"))

	providerMock := mock_snyk.NewMockIssueProvider(gomock.NewController(t))
	issues := []types.Issue{issue}
	providerMock.EXPECT().IssuesForRange(path, converter.FromRange(r)).Return(issues).AnyTimes()
	fileWatcher := watcher.NewFileWatcher()
	service := codeaction.NewService(c, providerMock, fileWatcher, notification.NewMockNotifier(), featureflag.NewFakeService())

	codeActionsParam := types.CodeActionParams{
		TextDocument: sglsp.TextDocumentIdentifier{
			URI: uriPath,
		},
		Range:   r,
		Context: types.CodeActionContext{},
	}
	return service, codeActionsParam, fileWatcher
}
