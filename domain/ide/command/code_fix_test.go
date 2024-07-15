/*
 * © 2023-2024 Snyk Limited
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

package command

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

var sampleRangeArg = map[string]interface{}{
	"Start": map[string]interface{}{
		"Line":      float64(1),
		"Character": float64(1),
	},
	"End": map[string]interface{}{
		"Line":      float64(1),
		"Character": float64(10),
	},
}
var codeActionId = uuid.New()
var sampleArgs = []any{codeActionId.String(), "test/path.js", sampleRangeArg}

type issueProviderMock struct {
	mock.Mock
}

func (m *issueProviderMock) Issues() snyk.IssuesByFile {
	panic("this should not be called")
}

func (m *issueProviderMock) Issue(_ string) snyk.Issue {
	panic("this should not be called")
}

func (m *issueProviderMock) IssuesForRange(path string, r snyk.Range) []snyk.Issue {
	args := m.Called(path, r)
	return args.Get(0).([]snyk.Issue)
}

func (m *issueProviderMock) IssuesForFile(_ string) []snyk.Issue {
	panic("this should not be called")
}

func setupClientCapability(config *config.Config) {
	clientCapabilties := config.ClientCapabilities()
	clientCapabilties.Workspace.ApplyEdit = true
	config.SetClientCapabilities(clientCapabilties)
}

func setupCommand(mockNotifier *notification.MockNotifier) *fixCodeIssue {
	cmdData := types.CommandData{
		CommandId: types.CodeFixCommand,
		Arguments: sampleArgs,
	}
	cmd := &fixCodeIssue{
		command:  cmdData,
		notifier: mockNotifier,
		logger:   config.CurrentConfig().Logger(),
	}
	return cmd
}

func setupMockEdit() (edit *snyk.WorkspaceEdit, deferredEdit func() *snyk.WorkspaceEdit) {
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
	var deferredMockEdit = func() *snyk.WorkspaceEdit {
		return mockEdit
	}
	return mockEdit, deferredMockEdit
}

func setupSampleIssues(issueRange snyk.Range, codeAction snyk.CodeAction, cmdData types.CommandData) []snyk.Issue {
	return []snyk.Issue{{
		ID:          "SNYK-123",
		Range:       issueRange,
		Severity:    snyk.High,
		Product:     product.ProductCode,
		IssueType:   snyk.CodeSecurityVulnerability,
		Message:     "This is a dummy error (severity error)",
		CodeActions: []snyk.CodeAction{codeAction},
		CodelensCommands: []types.CommandData{
			cmdData,
		},
	}}
}

func Test_fixCodeIssue_ErrorsWhenNoCapability(t *testing.T) {
	c := testutil.UnitTest(t)
	cmd := &fixCodeIssue{
		logger: c.Logger(),
		command: types.CommandData{
			CommandId: types.CodeFixCommand,
			Arguments: []any{sampleArgs},
		},
	}

	_, err := cmd.Execute(context.Background())

	assert.Error(t, err)
	assert.ErrorContains(t, err, "Client doesn't support 'workspace/applyEdit' capability.")
}

func Test_fixCodeIssue_sendsSuccessfulEdit(t *testing.T) {
	c := testutil.UnitTest(t)
	// arrange
	setupClientCapability(c)

	mockNotifier := notification.NewMockNotifier()
	cmd := setupCommand(mockNotifier)

	filePath := sampleArgs[1]
	issueRange := cmd.toRange(sampleArgs[2])
	mockEdit, deferredMockEdit := setupMockEdit()
	codeAction := snyk.CodeAction{
		Uuid:         &codeActionId,
		DeferredEdit: &deferredMockEdit,
	}
	issues := setupSampleIssues(issueRange, codeAction, cmd.command)

	issueProviderMock := new(issueProviderMock)
	issueProviderMock.On("IssuesForRange", filePath, issueRange).Return(issues)
	cmd.issueProvider = issueProviderMock

	// act
	res, err := cmd.Execute(context.Background())

	// assert
	assert.NoError(t, err)
	assert.Nil(t, res)
	assert.Nil(t, issues[0].CodelensCommands) // verify commands are reset

	// Verify workspace edit is sent to the client
	workspaceEdit := converter.ToWorkspaceEdit(mockEdit)
	assert.Equal(t, []any{types.ApplyWorkspaceEditParams{Label: "Snyk Code fix", Edit: workspaceEdit}, types.CodeLensRefresh{}}, mockNotifier.SentMessages())
}

func Test_fixCodeIssue_noEdit(t *testing.T) {
	c := testutil.UnitTest(t)
	// arrange
	setupClientCapability(c)

	mockNotifier := notification.NewMockNotifier()
	cmd := setupCommand(mockNotifier)

	filePath := sampleArgs[1]
	issueRange := cmd.toRange(sampleArgs[2])
	deferredMockEdit := func() *snyk.WorkspaceEdit {
		return nil
	}
	codeAction := snyk.CodeAction{
		Uuid:         &codeActionId,
		DeferredEdit: &deferredMockEdit,
	}
	issues := setupSampleIssues(issueRange, codeAction, cmd.command)

	issueProviderMock := new(issueProviderMock)
	issueProviderMock.On("IssuesForRange", filePath, issueRange).Return(issues)
	cmd.issueProvider = issueProviderMock

	// act
	res, err := cmd.Execute(context.Background())

	// assert
	assert.NoError(t, err)
	assert.Nil(t, res)
	assert.NotNil(t, issues[0].CodelensCommands) // verify commands isn't reset

	var sentMessages []any
	// Verify no workspace edit is sent to the client
	assert.Equal(t, sentMessages, mockNotifier.SentMessages())
}

func Test_fixCodeIssue_NoIssueFound(t *testing.T) {
	c := testutil.UnitTest(t)
	// arrange
	setupClientCapability(c)

	mockNotifier := notification.NewMockNotifier()
	cmd := setupCommand(mockNotifier)

	filePath := sampleArgs[1]
	issueRange := cmd.toRange(sampleArgs[2])

	issueProviderMock := new(issueProviderMock)
	issueProviderMock.On("IssuesForRange", filePath, issueRange).Return([]snyk.Issue{})
	cmd.issueProvider = issueProviderMock

	// act
	res, err := cmd.Execute(context.Background())

	// assert
	assert.Error(t, err)
	assert.ErrorContains(t, err, "Failed to find autofix code action.")
	assert.Nil(t, res)

	var expectedMsg []any
	// Verify no workspace edit is sent to the client
	assert.Equal(t, expectedMsg, mockNotifier.SentMessages())
}
