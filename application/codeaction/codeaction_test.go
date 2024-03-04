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

	"github.com/google/uuid"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/snyk/snyk-ls/application/codeaction"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/watcher"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
)

type mockIssuesProvider struct {
	mock.Mock
}

func (m *mockIssuesProvider) Issue(id string) snyk.Issue {
	return snyk.Issue{ID: id}
}

func (m *mockIssuesProvider) IssuesFor(path string, r snyk.Range) []snyk.Issue {
	args := m.Called(path, r)
	return args.Get(0).([]snyk.Issue)
}

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
	expectedIssue := snyk.Issue{
		CodeActions: []snyk.CodeAction{
			{
				Title:   "Fix this",
				Command: &code.FakeCommand,
			},
		},
	}
	service, codeActionsParam, _ := setupWithSingleIssue(expectedIssue)

	// Act
	actions := service.GetCodeActions(codeActionsParam)

	// Assert
	assert.Len(t, actions, 1)
	assert.Equal(t, expectedIssue.CodeActions[0].Command.CommandId, actions[0].Command.Command)
}

func Test_GetCodeActions_FileIsDirty_ReturnsEmptyResults(t *testing.T) {
	testutil.UnitTest(t)
	fakeIssue := snyk.Issue{
		CodeActions: []snyk.CodeAction{
			{
				Title:   "Fix this",
				Command: &code.FakeCommand,
			},
		},
	}
	service, codeActionsParam, w := setupWithSingleIssue(fakeIssue)
	w.SetFileAsChanged(codeActionsParam.TextDocument.URI) // File is dirty until it is saved

	// Act
	actions := service.GetCodeActions(codeActionsParam)

	// Assert
	assert.Empty(t, actions)
}

func Test_GetCodeActions_NoIssues_ReturnsNil(t *testing.T) {
	testutil.UnitTest(t)
	// It doesn't seem like there's a difference between returning a nil and returning an empty array. If this assumption
	// is proved to be false, this test can be changed.
	// Arrange

	var issues []snyk.Issue
	providerMock := new(mockIssuesProvider)
	providerMock.On("IssuesFor", mock.Anything, mock.Anything).Return(issues)
	fakeClient := &code.FakeSnykCodeClient{}
	snykCodeClient := fakeClient
	service := codeaction.NewService(config.CurrentConfig(), providerMock, watcher.NewFileWatcher(), notification.NewNotifier(), snykCodeClient)
	codeActionsParam := lsp.CodeActionParams{
		TextDocument: sglsp.TextDocumentIdentifier{
			URI: documentUriExample,
		},
		Range:   exampleRange,
		Context: lsp.CodeActionContext{},
	}

	// Act
	actions := service.GetCodeActions(codeActionsParam)

	// Assert
	assert.Nil(t, actions)
}

func Test_ResolveCodeAction_ReturnsCorrectEdit(t *testing.T) {
	testutil.UnitTest(t)
	// Arrange

	var mockTextEdit = snyk.TextEdit{
		Range: snyk.Range{
			Start: snyk.Position{Line: 1, Character: 2},
			End:   snyk.Position{Line: 3, Character: 4}},
		NewText: "someText",
	}
	var mockEdit = &snyk.WorkspaceEdit{
		Changes: map[string][]snyk.TextEdit{
			"someUri": {mockTextEdit},
		},
	}
	deferredEdit := func() *snyk.WorkspaceEdit {
		return mockEdit
	}
	id := uuid.New()
	expectedIssue := snyk.Issue{
		CodeActions: []snyk.CodeAction{
			{
				Title:        "Fix this",
				DeferredEdit: &deferredEdit,
				Uuid:         &id,
			},
		},
	}
	service, codeActionsParam, _ := setupWithSingleIssue(expectedIssue)

	// Act
	actions := service.GetCodeActions(codeActionsParam)
	actionFromRequest := actions[0]
	resolvedAction, _ := service.ResolveCodeAction(actionFromRequest, nil)

	// Assert
	assert.NotNil(t, resolvedAction)
	assert.Equal(t, lsp.CodeActionData(id), *resolvedAction.Data)
	assert.Nil(t, actionFromRequest.Edit)
	assert.Nil(t, actionFromRequest.Command)
	assert.NotNil(t, resolvedAction.Edit)
}

func Test_ResolveCodeAction_KeyDoesNotExist_ReturnError(t *testing.T) {
	testutil.UnitTest(t)
	// Arrange
	service := setupService()

	id := lsp.CodeActionData(uuid.New())
	ca := lsp.CodeAction{
		Title:   "Made up CA",
		Edit:    nil,
		Command: nil,
		Data:    &id,
	}

	// Act
	var err error
	_, err = service.ResolveCodeAction(ca, nil)

	// Assert
	assert.Error(t, err, "Expected error when resolving a code action with a key that doesn't exist")
}

func Test_ResolveCodeAction_UnknownCommandIsReported(t *testing.T) {
	testutil.UnitTest(t)
	// Arrange
	service := setupService()
	command.SetService(command.NewService(nil, nil, nil, nil, nil))

	id := lsp.CodeActionData(uuid.New())
	c := &sglsp.Command{
		Title:     "test",
		Command:   "test",
		Arguments: []any{"test"},
	}
	ca := lsp.CodeAction{
		Title:   "Made up CA",
		Edit:    nil,
		Command: c,
		Data:    &id,
	}

	// Act
	var err error
	_, err = service.ResolveCodeAction(ca, nil)

	// Assert
	assert.Error(t, err, "Command factory should have been called with fake command and returned not found err")
	assert.Contains(t, err.Error(), "unknown command")
}

func Test_ResolveCodeAction_CommandIsExecuted(t *testing.T) {
	testutil.UnitTest(t)
	// Arrange
	service := setupService()

	id := lsp.CodeActionData(uuid.New())
	command.SetService(snyk.NewCommandServiceMock())

	c := &sglsp.Command{
		Title:   snyk.LoginCommand,
		Command: snyk.LoginCommand,
	}
	ca := lsp.CodeAction{
		Title:   "Made up CA",
		Edit:    nil,
		Command: c,
		Data:    &id,
	}

	_, err := service.ResolveCodeAction(ca, nil)
	assert.NoError(t, err, "command should be called without error")

	serviceMock := command.Service().(*snyk.CommandServiceMock)
	assert.Len(t, serviceMock.ExecutedCommands(), 1)
	assert.Equal(t, serviceMock.ExecutedCommands()[0].CommandId, c.Command)
}

func Test_ResolveCodeAction_KeyIsNull_ReturnsError(t *testing.T) {
	testutil.UnitTest(t)
	service := setupService()

	ca := lsp.CodeAction{
		Title:   "Made up CA",
		Edit:    nil,
		Command: nil,
		Data:    nil,
	}

	_, err := service.ResolveCodeAction(ca, nil)
	assert.Error(t, err, "Expected error when resolving a code action with a null key")
	assert.True(t, codeaction.IsMissingKeyError(err))
}

func setupService() *codeaction.CodeActionsService {
	providerMock := new(mockIssuesProvider)
	providerMock.On("IssuesFor", mock.Anything, mock.Anything).Return([]snyk.Issue{})
	fakeClient := &code.FakeSnykCodeClient{}
	snykCodeClient := fakeClient
	service := codeaction.NewService(config.CurrentConfig(), providerMock, watcher.NewFileWatcher(), notification.NewNotifier(), snykCodeClient)
	return service
}

func setupWithSingleIssue(issue snyk.Issue) (*codeaction.CodeActionsService, lsp.CodeActionParams, *watcher.FileWatcher) {
	r := exampleRange
	uriPath := documentUriExample
	path := uri.PathFromUri(uriPath)
	providerMock := new(mockIssuesProvider)
	issues := []snyk.Issue{issue}
	providerMock.On("IssuesFor", path, converter.FromRange(r)).Return(issues)
	fileWatcher := watcher.NewFileWatcher()
	fakeClient := &code.FakeSnykCodeClient{}
	snykCodeClient := fakeClient
	service := codeaction.NewService(config.CurrentConfig(), providerMock, fileWatcher, notification.NewNotifier(), snykCodeClient)

	codeActionsParam := lsp.CodeActionParams{
		TextDocument: sglsp.TextDocumentIdentifier{
			URI: uriPath,
		},
		Range:   r,
		Context: lsp.CodeActionContext{},
	}
	return service, codeActionsParam, fileWatcher
}
