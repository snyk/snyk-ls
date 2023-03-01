package codeaction_test

import (
	"testing"

	"github.com/google/uuid"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/snyk/snyk-ls/application/codeaction"
	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/application/watcher"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/uri"
)

type mockIssuesProvider struct {
	mock.Mock
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
	// Arrange
	t.Parallel()
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
	// Arrange
	t.Parallel()
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
	// It doesn't seem like there's a difference between returning a nil and returning an empty array. If this assumption
	// is proved to be false, this test can be changed.
	// Arrange
	t.Parallel()
	var issues []snyk.Issue
	providerMock := new(mockIssuesProvider)
	providerMock.On("IssuesFor", mock.Anything, mock.Anything).Return(issues)
	//service := codeaction.CodeActionsService{
	//	IssuesProvider: providerMock,
	//}
	service := codeaction.NewService(providerMock, watcher.NewFileWatcher())
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
	// Arrange
	t.Parallel()
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
	resolvedAction, _ := service.ResolveCodeAction(actionFromRequest)

	// Assert
	assert.NotNil(t, resolvedAction)
	assert.Equal(t, lsp.CodeActionData(id), *resolvedAction.Data)
	assert.Nil(t, actionFromRequest.Edit)
	assert.Nil(t, actionFromRequest.Command)
	assert.NotNil(t, resolvedAction.Edit)
}

func Test_ResolveCodeAction_KeyDoesNotExist_ReturnError(t *testing.T) {
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
	//var resolvedAction lsp.CodeAction
	_, err = service.ResolveCodeAction(ca)

	// Assert
	assert.Error(t, err, "Expected error when resolving a code action with a key that doesn't exist")
}

func setupService() *codeaction.CodeActionsService {
	providerMock := new(mockIssuesProvider)
	providerMock.On("IssuesFor", mock.Anything, mock.Anything).Return([]snyk.Issue{})
	service := codeaction.NewService(providerMock, watcher.NewFileWatcher())
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
	service := codeaction.NewService(providerMock, fileWatcher)

	codeActionsParam := lsp.CodeActionParams{
		TextDocument: sglsp.TextDocumentIdentifier{
			URI: uriPath,
		},
		Range:   r,
		Context: lsp.CodeActionContext{},
	}
	return service, codeActionsParam, fileWatcher
}
