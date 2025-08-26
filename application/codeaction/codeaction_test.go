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
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
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
	testutil.UnitTest(t)
	expectedIssue := &snyk.Issue{
		CodeActions: []types.CodeAction{
			&snyk.CodeAction{
				Title:   "Fix this",
				Command: &code.FakeCommand,
			},
		},
	}
	service, codeActionsParam, _ := setupWithSingleIssue(t, expectedIssue)

	// Act
	actions := service.GetCodeActions(codeActionsParam)

	// Assert
	assert.Len(t, actions, 1)
	assert.Equal(t, expectedIssue.CodeActions[0].GetCommand().CommandId, actions[0].Command.Command)
}

func Test_GetCodeActions_FileIsDirty_ReturnsEmptyResults(t *testing.T) {
	testutil.UnitTest(t)
	fakeIssue := &snyk.Issue{
		CodeActions: []types.CodeAction{
			&snyk.CodeAction{
				Title:   "Fix this",
				Command: &code.FakeCommand,
			},
		},
	}
	service, codeActionsParam, w := setupWithSingleIssue(t, fakeIssue)
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
	ctrl := gomock.NewController(t)
	var issues []types.Issue
	providerMock := mock_snyk.NewMockIssueProvider(ctrl)
	providerMock.EXPECT().IssuesForRange(gomock.Any(), gomock.Any()).Return(issues)
	fakeClient := &code.FakeSnykCodeClient{C: c}
	snykCodeClient := fakeClient
	service := codeaction.NewService(config.CurrentConfig(), providerMock, watcher.NewFileWatcher(), notification.NewMockNotifier(), snykCodeClient)
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
	testutil.UnitTest(t)
	// Arrange

	var mockTextEdit = types.TextEdit{
		Range: types.Range{
			Start: types.Position{Line: 1, Character: 2},
			End:   types.Position{Line: 3, Character: 4}},
		NewText: "someText",
	}
	var mockEdit = &types.WorkspaceEdit{
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
				Title:        "Fix this",
				DeferredEdit: &deferredEdit,
				Uuid:         &id,
			},
		},
	}
	service, codeActionsParam, _ := setupWithSingleIssue(t, expectedIssue)

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
	testutil.UnitTest(t)
	// Arrange
	service := setupService(t)

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
	testutil.UnitTest(t)
	service := setupService(t)

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
	testutil.UnitTest(t)
	service := setupService(t)

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
	service := setupService(t)

	quickFix := &snyk.CodeAction{Title: "Upgrade to logback-core:1.3.15"}

	quickFixGroupables := []types.Groupable{quickFix}

	issues := []types.Issue{
		&snyk.Issue{},
		&snyk.Issue{},
		&snyk.Issue{},
		&snyk.Issue{},
		&snyk.Issue{},
	}

		// First call to UpdateIssuesWithQuickFix
	service.UpdateIssuesWithQuickFix(quickFixGroupables, issues)

	// Check the title directly on the quickfix action
	expectedAfterFirstCall := "Upgrade to logback-core:1.3.15 and fix 1 issue (4 unfixable)"
	assert.Equal(t, expectedAfterFirstCall, quickFix.GetTitle())

		// Second call - this should demonstrate the concatenation issue
	// The title will now include the previous "and fix X issue" text
	service.UpdateIssuesWithQuickFix(quickFixGroupables, issues)

	// The title should NOT be concatenated - this test will fail if the bug exists
	// The title should remain the same as after the first call
	expectedAfterSecondCall := "Upgrade to logback-core:1.3.15 and fix 1 issue (4 unfixable)"
	assert.Equal(t, expectedAfterSecondCall, quickFix.GetTitle(),
		"Title should not be concatenated on second call. Expected: %s, Got: %s",
		expectedAfterSecondCall, quickFix.GetTitle())

		// Third call - title should still not be concatenated
	service.UpdateIssuesWithQuickFix(quickFixGroupables, issues)

	// The title should NOT be concatenated three times - this test will fail if the bug exists
	expectedAfterThirdCall := "Upgrade to logback-core:1.3.15 and fix 1 issue (4 unfixable)"
	assert.Equal(t, expectedAfterThirdCall, quickFix.GetTitle(),
		"Title should not be concatenated on third call. Expected: %s, Got: %s",
		expectedAfterThirdCall, quickFix.GetTitle())

	// This test will fail if the concatenation bug exists
	// Each call to UpdateIssuesWithQuickFix should use the original title, not append to existing
	t.Logf("Title after 1st call: %s", expectedAfterFirstCall)
	t.Logf("Title after 2nd call: %s", quickFix.GetTitle())
	t.Logf("Title after 3rd call: %s", quickFix.GetTitle())

	// Additional assertion: verify that titles are not growing
	originalTitleLength := len("Upgrade to logback-core:1.3.15")
	assert.False(t, len(quickFix.GetTitle()) > originalTitleLength + 50,
		"Title should not grow significantly. Original length: %d, Current length: %d",
		originalTitleLength, len(quickFix.GetTitle()))
}

func setupService(t *testing.T) *codeaction.CodeActionsService {
	t.Helper()
	providerMock := mock_snyk.NewMockIssueProvider(gomock.NewController(t))
	providerMock.EXPECT().IssuesForRange(gomock.Any(), gomock.Any()).Return([]types.Issue{}).AnyTimes()
	fakeClient := &code.FakeSnykCodeClient{C: config.CurrentConfig()}
	snykCodeClient := fakeClient
	service := codeaction.NewService(config.CurrentConfig(), providerMock, watcher.NewFileWatcher(), notification.NewMockNotifier(), snykCodeClient)
	return service
}

func setupWithSingleIssue(t *testing.T, issue types.Issue) (*codeaction.CodeActionsService, types.CodeActionParams, *watcher.FileWatcher) {
	t.Helper()
	r := exampleRange
	uriPath := documentUriExample
	path := uri.PathFromUri(uriPath)
	providerMock := mock_snyk.NewMockIssueProvider(gomock.NewController(t))
	issues := []types.Issue{issue}
	providerMock.EXPECT().IssuesForRange(path, converter.FromRange(r)).Return(issues).AnyTimes()
	fileWatcher := watcher.NewFileWatcher()
	fakeClient := &code.FakeSnykCodeClient{C: config.CurrentConfig()}
	snykCodeClient := fakeClient
	service := codeaction.NewService(config.CurrentConfig(), providerMock, fileWatcher, notification.NewMockNotifier(), snykCodeClient)

	codeActionsParam := types.CodeActionParams{
		TextDocument: sglsp.TextDocumentIdentifier{
			URI: uriPath,
		},
		Range:   r,
		Context: types.CodeActionContext{},
	}
	return service, codeActionsParam, fileWatcher
}
