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

package snyk

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/types"
)

var mockTextEdit = TextEdit{
	Range: Range{
		Start: Position{Line: 1, Character: 2},
		End:   Position{Line: 3, Character: 4}},
	NewText: "someText",
}

var mockEdit = &WorkspaceEdit{
	Changes: map[string][]TextEdit{
		"someUri": {mockTextEdit},
	},
}

var mockCommand = &types.CommandData{
	Title: "command",
}

var mockDeferredEdit = func() *WorkspaceEdit {
	return mockEdit
}

var mockDeferredCommand = func() *types.CommandData {
	return mockCommand
}

func Test_NewCodeAction_NoEditOrCommand_Errors(t *testing.T) {
	_, err := NewCodeAction("title", nil, nil)
	assert.Error(t, err)
}

func Test_NewDeferredCodeAction_NoEditOrCommand_Errors(t *testing.T) {
	_, err := NewDeferredCodeAction("title", nil, nil, "", nil)
	assert.Error(t, err)
}

func Test_NewCodeAction(t *testing.T) {
	action, err := NewCodeAction("title", mockEdit, mockCommand)
	assertActionsInitializedCorrectly(t, err, action, mockEdit, mockCommand, nil, nil)
}

func Test_NewDeferredCodeAction(t *testing.T) {
	action, err := NewDeferredCodeAction("title", &mockDeferredEdit, &mockDeferredCommand, "", nil)

	assertActionsInitializedCorrectly(t,
		err,
		action,
		(*WorkspaceEdit)(nil),
		(*types.CommandData)(nil),
		&mockDeferredEdit,
		&mockDeferredCommand)
	assert.NotNil(t, action.Uuid, "UUID should be initialized")
}

func assertActionsInitializedCorrectly(t *testing.T,
	err error,
	action CodeAction,
	expectedEdit *WorkspaceEdit,
	expectedCommand *types.CommandData,
	mockDeferredEdit *func() *WorkspaceEdit,
	mockDeferredCommand *func() *types.CommandData,
) {
	t.Helper()
	assert.NoError(t, err)
	assert.Equal(t, "title", action.Title)
	assert.Equal(t, expectedEdit, action.Edit)
	assert.Equal(t, expectedCommand, action.Command)
	assert.Equal(t, mockDeferredEdit, action.DeferredEdit)
	assert.Equal(t, mockDeferredCommand, action.DeferredCommand)
}
