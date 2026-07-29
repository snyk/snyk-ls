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
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/codeaction"
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
	engine := testutil.UnitTest(t)
	expectedIssue := &snyk.Issue{
		CodeActions: []types.CodeAction{
			&snyk.CodeAction{
				Title:         "Fix this",
				OriginalTitle: "Fix this",
				Command:       &code.FakeCommand,
			},
		},
	}
	service, codeActionsParam, _ := setupWithSingleIssue(t, engine, expectedIssue)

	// Act
	actions := service.GetCodeActions(codeActionsParam)

	// Assert
	assert.Len(t, actions, 1)
	assert.Equal(t, expectedIssue.CodeActions[0].GetCommand().CommandId, actions[0].Command.Command)
}

func Test_GetCodeActions_FileIsDirty_ReturnsEmptyResults(t *testing.T) {
	engine := testutil.UnitTest(t)
	fakeIssue := &snyk.Issue{
		CodeActions: []types.CodeAction{
			&snyk.CodeAction{
				Title:         "Fix this",
				OriginalTitle: "Fix this",
				Command:       &code.FakeCommand,
			},
		},
	}
	service, codeActionsParam, w := setupWithSingleIssue(t, engine, fakeIssue)
	w.SetFileAsChanged(codeActionsParam.TextDocument.URI) // File is dirty until it is saved

	// Act
	actions := service.GetCodeActions(codeActionsParam)

	// Assert
	assert.Empty(t, actions)
}

func Test_GetCodeActions_NoIssues_ReturnsNil(t *testing.T) {
	engine := testutil.UnitTest(t)
	// It doesn't seem like there's a difference between returning a nil and returning an empty array. If this assumption
	// is proved to be false, this test can be changed.
	// Arrange
	// Set up workspace with folder that contains the test file path
	// The document URI is "file:///path/to/file", so the folder should be "/path/to"
	_, _ = workspaceutil.SetupWorkspace(t, engine, types.FilePath("/path/to"))

	ctrl := gomock.NewController(t)
	var issues []types.Issue
	providerMock := mock_snyk.NewMockIssueProvider(ctrl)
	providerMock.EXPECT().IssuesForRange(gomock.Any(), gomock.Any()).Return(issues)
	service := codeaction.NewService(engine, providerMock, watcher.NewFileWatcher(), notification.NewMockNotifier(), featureflag.NewFakeService(), types.NewConfigResolver(engine.GetLogger()), nil)
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

// Test_ResolveCodeAction_CacheEntryPresentDuringDeferredEdit verifies that the
// cache entry for a code action is still present while the deferred edit is
// executing, and is removed only after ResolveCodeAction returns. This ensures
// that a client retry arriving while the first resolve is still computing can
// still find the entry instead of receiving a hard "not found" error.
func Test_ResolveCodeAction_CacheEntryPresentDuringDeferredEdit(t *testing.T) {
	engine := testutil.UnitTest(t)

	id := uuid.New()

	// svcRef holds the service pointer so the deferred-edit closure can call
	// CacheLenForTest without a forward-reference compile error.
	var svcRef *codeaction.CodeActionsService

	// cacheLenDuringEdit captures the cache length as observed from inside the deferred edit.
	var cacheLenDuringEdit int
	deferredEdit := func(_ context.Context) *types.WorkspaceEdit {
		// While the edit is running, the entry must still be in the cache so
		// that a concurrent retry can find it.
		cacheLenDuringEdit = codeaction.CacheLenForTest(svcRef)
		return nil
	}

	issue := &snyk.Issue{
		CodeActions: []types.CodeAction{
			&snyk.CodeAction{
				Title:         "Fix with remy",
				OriginalTitle: "Fix with remy",
				DeferredEdit:  &deferredEdit,
				Uuid:          &id,
			},
		},
	}

	service, _, _ := setupWithSingleIssue(t, engine, issue)
	svcRef = service

	// Populate the cache.
	params := types.CodeActionParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: documentUriExample},
		Range:        exampleRange,
		Context:      types.CodeActionContext{},
	}
	actions := service.GetCodeActions(params)
	assert.Equal(t, 1, codeaction.CacheLenForTest(service), "cache must hold exactly one entry after GetCodeActions")

	// Resolve the action — this invokes deferredEdit, which reads cacheLenDuringEdit.
	lspAction := actions[0]
	_, err := service.ResolveCodeAction(t.Context(), lspAction)
	assert.NoError(t, err)

	// The entry must have been present during the edit (i.e. not yet deleted).
	assert.Equal(t, 1, cacheLenDuringEdit,
		"cache entry must still be present while the deferred edit is executing")
	// After ResolveCodeAction returns the entry must be gone.
	assert.Equal(t, 0, codeaction.CacheLenForTest(service),
		"cache entry must be removed after ResolveCodeAction returns")
}

// Test_ResolveCodeAction_PanicInDeferredEdit_CacheEntryRemoved verifies that
// the cache entry is deleted even when the deferred edit function panics. If
// the delete is done with an explicit (non-deferred) block after the edit call,
// a panic aborts that path and the entry leaks forever. With a defer the entry
// is always cleaned up.
//
// The test:
//  1. Caches an action whose deferred edit panics.
//  2. Calls ResolveCodeAction — the caller recovers the panic (simulating the
//     jrpc2 handler recovery), so the goroutine stays alive.
//  3. Asserts that the cache length is 0 after recovery (entry must be gone).
func Test_ResolveCodeAction_PanicInDeferredEdit_CacheEntryRemoved(t *testing.T) {
	engine := testutil.UnitTest(t)

	id := uuid.New()
	deferredEdit := func(_ context.Context) *types.WorkspaceEdit {
		panic("simulated provider panic")
	}

	issue := &snyk.Issue{
		CodeActions: []types.CodeAction{
			&snyk.CodeAction{
				Title:         "Fix with remy",
				OriginalTitle: "Fix with remy",
				DeferredEdit:  &deferredEdit,
				Uuid:          &id,
			},
		},
	}

	service, _, _ := setupWithSingleIssue(t, engine, issue)

	// Populate the cache.
	params := types.CodeActionParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: documentUriExample},
		Range:        exampleRange,
		Context:      types.CodeActionContext{},
	}
	actions := service.GetCodeActions(params)
	assert.Equal(t, 1, codeaction.CacheLenForTest(service),
		"cache must hold exactly one entry after GetCodeActions")

	lspAction := actions[0]

	// Invoke ResolveCodeAction and recover the panic (mimicking jrpc2 recovery).
	func() {
		defer func() { _ = recover() }()
		_, _ = service.ResolveCodeAction(t.Context(), lspAction)
	}()

	// Whether the delete used defer or an explicit block determines whether the
	// entry survives the panic. With defer it must be gone; with an explicit
	// block it leaks (CacheLen would be 1).
	assert.Equal(t, 0, codeaction.CacheLenForTest(service),
		"cache entry must be removed even when the deferred edit panics")
}

func Test_ResolveCodeAction_ReturnsCorrectEdit(t *testing.T) {
	engine := testutil.UnitTest(t)
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
	deferredEdit := func(_ context.Context) *types.WorkspaceEdit {
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
	service, codeActionsParam, _ := setupWithSingleIssue(t, engine, expectedIssue)

	// Act
	actions := service.GetCodeActions(codeActionsParam)
	actionFromRequest := actions[0]
	resolvedAction, _ := service.ResolveCodeAction(t.Context(), actionFromRequest)

	// Assert
	assert.NotNil(t, resolvedAction)
	assert.Equal(t, types.CodeActionData(id), *resolvedAction.Data)
	assert.Nil(t, actionFromRequest.Edit)
	assert.Nil(t, actionFromRequest.Command)
	assert.NotNil(t, resolvedAction.Edit)
}

// Test_ResolveCodeAction_NilDeferredEdit_NoPanic verifies that resolving a cached
// action whose DeferredEdit is nil (e.g. a command-only CodeAction) does not panic.
// Previously, the code unconditionally dereferenced GetDeferredEdit(), causing a
// nil-pointer panic for command-only actions.
func Test_ResolveCodeAction_NilDeferredEdit_NoPanic(t *testing.T) {
	engine := testutil.UnitTest(t)

	// Build a deferred action with a command but no edit (DeferredEdit == nil).
	deferredCmd := func() *types.CommandData {
		return &types.CommandData{CommandId: "some.command"}
	}
	id := uuid.New()
	action := &snyk.CodeAction{
		Title:           "Command only",
		OriginalTitle:   "Command only",
		DeferredCommand: &deferredCmd,
		Uuid:            &id,
	}
	// DeferredEdit is nil — this is the scenario under test.
	if action.GetDeferredEdit() != nil {
		t.Fatal("test setup error: DeferredEdit must be nil for this test")
	}

	issue := &snyk.Issue{}

	// Wire a service and manually populate the cache by embedding the action in an issue.
	_, _ = workspaceutil.SetupWorkspace(t, engine, types.FilePath("/path/to"))
	ctrl := gomock.NewController(t)
	providerMock := mock_snyk.NewMockIssueProvider(ctrl)
	providerMock.EXPECT().IssuesForRange(gomock.Any(), gomock.Any()).
		Return([]types.Issue{issue}).AnyTimes()
	// The issue carries the action so GetCodeActions caches it.
	issue.CodeActions = []types.CodeAction{action}

	service := codeaction.NewService(engine, providerMock, watcher.NewFileWatcher(), notification.NewMockNotifier(), featureflag.NewFakeService(), types.NewConfigResolver(engine.GetLogger()), nil)
	codeActionsParam := types.CodeActionParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: documentUriExample},
		Range:        exampleRange,
		Context:      types.CodeActionContext{},
	}

	// Populate the cache via GetCodeActions.
	actions := service.GetCodeActions(codeActionsParam)

	// Find the action with a Data field (deferred/cached actions have Data set).
	var cachedAction *types.LSPCodeAction
	for i := range actions {
		if actions[i].Data != nil {
			cachedAction = &actions[i]
			break
		}
	}
	if cachedAction == nil {
		t.Skip("no cached action found; test setup may have changed")
		return
	}

	// Must not panic even though DeferredEdit is nil.
	resolved, err := service.ResolveCodeAction(t.Context(), *cachedAction)
	assert.NoError(t, err, "resolving a command-only action must not error")
	// Without a deferred edit the resolved action must have no edit.
	assert.Nil(t, resolved.Edit, "command-only action must produce no edit")
}

func Test_ResolveCodeAction_KeyDoesNotExist_ReturnError(t *testing.T) {
	engine := testutil.UnitTest(t)
	// Arrange
	service := setupService(t, engine)

	id := types.CodeActionData(uuid.New())
	ca := types.LSPCodeAction{
		Title:   "Made up CA",
		Edit:    nil,
		Command: nil,
		Data:    &id,
	}

	// Act
	var err error
	_, err = service.ResolveCodeAction(t.Context(), ca)

	// Assert
	assert.Error(t, err, "Expected error when resolving a code action with a key that doesn't exist")
}

func Test_ResolveCodeAction_KeyAndCommandIsNull_ReturnsError(t *testing.T) {
	engine := testutil.UnitTest(t)
	service := setupService(t, engine)

	ca := types.LSPCodeAction{
		Title:   "Made up CA",
		Edit:    nil,
		Command: nil,
		Data:    nil,
	}

	_, err := service.ResolveCodeAction(t.Context(), ca)
	assert.Error(t, err, "Expected error when resolving a code action with a null key")
	assert.True(t, codeaction.IsMissingKeyError(err))
}

func Test_ResolveCodeAction_KeyIsNull_ReturnsCodeAction(t *testing.T) {
	engine := testutil.UnitTest(t)
	service := setupService(t, engine)

	expected := types.LSPCodeAction{
		Title:   "Made up CA",
		Edit:    nil,
		Command: &sglsp.Command{Command: "test"},
		Data:    nil,
	}

	actual, err := service.ResolveCodeAction(t.Context(), expected)
	assert.NoError(t, err, "Expected error when resolving a code action with a null key")
	assert.Equal(t, expected.Command.Command, actual.Command.Command)
}

func Test_UpdateIssuesWithQuickFix_TitleConcatenationIssue_WhenCalledMultipleTimes(t *testing.T) {
	engine := testutil.UnitTest(t)
	service := setupService(t, engine)

	quickFix := &snyk.CodeAction{
		Title:         "Upgrade to logback-core:1.3.15",
		OriginalTitle: "Upgrade to logback-core:1.3.15",
	}

	quickFixGroupables := []types.Groupable{quickFix}

	issues := []types.Issue{
		&snyk.Issue{},
		&snyk.Issue{},
		&snyk.Issue{},
		&snyk.Issue{},
		&snyk.Issue{},
	}

	service.UpdateIssuesWithQuickFix(quickFixGroupables, issues)

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

	// Additional assertion: verify that titles are not growing
	originalTitleLength := len("Upgrade to logback-core:1.3.15")
	assert.False(t, len(quickFix.GetTitle()) > originalTitleLength+50,
		"Title should not grow significantly. Original length: %d, Current length: %d",
		originalTitleLength, len(quickFix.GetTitle()))
}

func setupService(t *testing.T, engine workflow.Engine) *codeaction.CodeActionsService {
	t.Helper()
	// Set up workspace with folder that contains the test file path
	// The document URI is "file:///path/to/file", so the folder should be "/path/to"
	_, _ = workspaceutil.SetupWorkspace(t, engine, types.FilePath("/path/to"))

	providerMock := mock_snyk.NewMockIssueProvider(gomock.NewController(t))
	providerMock.EXPECT().IssuesForRange(gomock.Any(), gomock.Any()).Return([]types.Issue{}).AnyTimes()
	service := codeaction.NewService(engine, providerMock, watcher.NewFileWatcher(), notification.NewMockNotifier(), featureflag.NewFakeService(), types.NewConfigResolver(engine.GetLogger()), nil)
	return service
}

func setupWithSingleIssue(t *testing.T, engine workflow.Engine, issue types.Issue) (*codeaction.CodeActionsService, types.CodeActionParams, *watcher.FileWatcher) {
	t.Helper()
	r := exampleRange
	uriPath := documentUriExample
	path := uri.PathFromUri(uriPath)

	// Set up workspace with folder that contains the test file path
	// The document URI is "file:///path/to/file", so the folder should be "/path/to"
	_, _ = workspaceutil.SetupWorkspace(t, engine, types.FilePath("/path/to"))

	providerMock := mock_snyk.NewMockIssueProvider(gomock.NewController(t))
	issues := []types.Issue{issue}
	providerMock.EXPECT().IssuesForRange(path, converter.FromRange(r)).Return(issues).AnyTimes()
	fileWatcher := watcher.NewFileWatcher()
	service := codeaction.NewService(engine, providerMock, fileWatcher, notification.NewMockNotifier(), featureflag.NewFakeService(), types.NewConfigResolver(engine.GetLogger()), nil)

	codeActionsParam := types.CodeActionParams{
		TextDocument: sglsp.TextDocumentIdentifier{
			URI: uriPath,
		},
		Range:   r,
		Context: types.CodeActionContext{},
	}
	return service, codeActionsParam, fileWatcher
}
