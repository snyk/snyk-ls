package snyk_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/snyk"
)

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

var mockCommand = &snyk.CommandData{
	Title: "command",
}

var mockDeferredEdit = func() *snyk.WorkspaceEdit {
	return mockEdit
}

var mockDeferredCommand = func() *snyk.CommandData {
	return mockCommand
}

func Test_NewCodeAction_NoEditOrCommand_Errors(t *testing.T) {
	t.Parallel()
	_, err := snyk.NewCodeAction("title", nil, nil)
	assert.Error(t, err)
}

func Test_NewDeferredCodeAction_NoEditOrCommand_Errors(t *testing.T) {
	t.Parallel()
	_, err := snyk.NewDeferredCodeAction("title", nil, nil)
	assert.Error(t, err)
}

func Test_NewCodeAction(t *testing.T) {
	t.Parallel()

	action, err := snyk.NewCodeAction("title", mockEdit, mockCommand)
	assertActionsInitializedCorrectly(t, err, action, mockEdit, mockCommand, nil, nil)
}

func Test_NewDeferredCodeAction(t *testing.T) {
	t.Parallel()

	action, err := snyk.NewDeferredCodeAction("title", &mockDeferredEdit, &mockDeferredCommand)

	assertActionsInitializedCorrectly(t,
		err,
		action,
		(*snyk.WorkspaceEdit)(nil),
		(*snyk.CommandData)(nil),
		&mockDeferredEdit,
		&mockDeferredCommand)
	assert.NotNil(t, action.Uuid, "UUID should be initialized")
}

func Test_NewPreferredCodeAction(t *testing.T) {
	t.Parallel()

	action, err := snyk.NewPreferredCodeAction("title", mockEdit, mockCommand)
	assertActionsInitializedCorrectly(t, err, action, mockEdit, mockCommand, nil, nil)
	assert.True(t, *action.IsPreferred)
}

func assertActionsInitializedCorrectly(t *testing.T,
	err error,
	action snyk.CodeAction,
	expectedEdit *snyk.WorkspaceEdit,
	expectedCommand *snyk.CommandData,
	mockDeferredEdit *func() *snyk.WorkspaceEdit,
	mockDeferredCommand *func() *snyk.CommandData,
) {
	t.Helper()
	assert.NoError(t, err)
	assert.Equal(t, "title", action.Title)
	assert.Equal(t, expectedEdit, action.Edit)
	assert.Equal(t, expectedCommand, action.Command)
	assert.Equal(t, mockDeferredEdit, action.DeferredEdit)
	assert.Equal(t, mockDeferredCommand, action.DeferredCommand)
}
