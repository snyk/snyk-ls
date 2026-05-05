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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/mock_snyk"
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

func setupClientCapability(engine workflow.Engine) {
	conf := engine.GetConfiguration()
	val := conf.Get(types.SettingClientCapabilities)
	var caps types.ClientCapabilities
	if val != nil {
		if c, ok := val.(types.ClientCapabilities); ok {
			caps = c
		}
	}
	caps.Workspace.ApplyEdit = true
	conf.Set(types.SettingClientCapabilities, caps)
}

func setupCommand(t *testing.T, engine workflow.Engine, mockNotifier *notification.MockNotifier) *fixCodeIssue {
	t.Helper()
	cmdData := types.CommandData{
		CommandId: types.CodeFixCommand,
		Arguments: sampleArgs,
	}
	cmd := &fixCodeIssue{
		command:  cmdData,
		notifier: mockNotifier,
		logger:   engine.GetLogger(),
		engine:   engine,
	}
	return cmd
}

func setupMockEdit() (edit *types.WorkspaceEdit, deferredEdit func() *types.WorkspaceEdit) {
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
	var deferredMockEdit = func() *types.WorkspaceEdit {
		return mockEdit
	}
	return mockEdit, deferredMockEdit
}

func setupSampleIssues(issueRange types.Range, codeAction snyk.CodeAction, cmdData types.CommandData) []types.Issue {
	return []types.Issue{&snyk.Issue{
		ID:          "SNYK-123",
		Range:       issueRange,
		Severity:    types.High,
		Product:     product.ProductCode,
		IssueType:   types.CodeSecurityVulnerability,
		Message:     "This is a dummy error (severity error)",
		CodeActions: []types.CodeAction{&codeAction},
		CodelensCommands: []types.CommandData{
			cmdData,
		},
	}}
}

func Test_fixCodeIssue_ErrorsWhenNoCapability(t *testing.T) {
	engine := testutil.UnitTest(t)
	cmd := &fixCodeIssue{
		logger: engine.GetLogger(),
		engine: engine,
		command: types.CommandData{
			CommandId: types.CodeFixCommand,
			Arguments: []any{sampleArgs},
		},
	}

	_, err := cmd.Execute(t.Context())

	assert.Error(t, err)
	assert.ErrorContains(t, err, "Client doesn't support 'workspace/applyEdit' capability.")
}

func Test_fixCodeIssue_sendsSuccessfulEdit(t *testing.T) {
	engine := testutil.UnitTest(t)
	// arrange
	setupClientCapability(engine)
	ctrl := gomock.NewController(t)

	mockNotifier := notification.NewMockNotifier()
	cmd := setupCommand(t, engine, mockNotifier)

	filePath := sampleArgs[1].(string)
	path := types.FilePath(filePath)
	issueRange, err := cmd.toRange(sampleArgs[2])
	require.NoError(t, err)
	mockEdit, deferredMockEdit := setupMockEdit()
	codeAction := snyk.CodeAction{
		Uuid:         &codeActionId,
		DeferredEdit: &deferredMockEdit,
	}
	issues := setupSampleIssues(issueRange, codeAction, cmd.command)
	issueMap := snyk.IssuesByFile{
		path: issues,
	}

	issueProviderMock := mock_snyk.NewMockCacheProvider(ctrl)
	issueProviderMock.EXPECT().Issues().Return(issueMap)
	cmd.issueProvider = issueProviderMock

	// act
	res, err := cmd.Execute(t.Context())

	// assert
	assert.NoError(t, err)
	assert.Nil(t, res)
	assert.Nil(t, issues[0].GetCodelensCommands()) // verify commands are reset

	// Verify workspace edit is sent to the client
	workspaceEdit := converter.ToWorkspaceEdit(mockEdit)
	assert.Equal(t, []any{types.ApplyWorkspaceEditParams{Label: "Snyk Code fix", Edit: workspaceEdit}, types.CodeLensRefresh{}}, mockNotifier.SentMessages())
}

func Test_fixCodeIssue_noEdit(t *testing.T) {
	engine := testutil.UnitTest(t)
	// arrange
	ctrl := gomock.NewController(t)
	setupClientCapability(engine)

	mockNotifier := notification.NewMockNotifier()
	cmd := setupCommand(t, engine, mockNotifier)

	filePath := sampleArgs[1].(string)
	path := types.FilePath(filePath)
	rangeDto, ok := sampleArgs[2].(RangeDto)
	require.True(t, ok)
	issueRange, err := cmd.toRange(rangeDto)
	require.NoError(t, err)
	deferredMockEdit := func() *types.WorkspaceEdit {
		return nil
	}
	codeAction := snyk.CodeAction{
		Uuid:         &codeActionId,
		DeferredEdit: &deferredMockEdit,
	}
	issues := setupSampleIssues(issueRange, codeAction, cmd.command)
	issueMap := snyk.IssuesByFile{
		path: issues,
	}

	issueProviderMock := mock_snyk.NewMockIssueProvider(ctrl)
	issueProviderMock.EXPECT().Issues().Return(issueMap)
	cmd.issueProvider = issueProviderMock

	// act
	res, err := cmd.Execute(t.Context())

	// assert
	assert.NoError(t, err)
	assert.Nil(t, res)
	assert.NotNil(t, issues[0].GetCodelensCommands()) // verify commands isn't reset

	var sentMessages []any
	// Verify no workspace edit is sent to the client
	assert.Equal(t, sentMessages, mockNotifier.SentMessages())
}

func Test_fixCodeIssue_NoIssueFound(t *testing.T) {
	engine := testutil.UnitTest(t)
	// arrange
	ctrl := gomock.NewController(t)
	setupClientCapability(engine)

	mockNotifier := notification.NewMockNotifier()
	cmd := setupCommand(t, engine, mockNotifier)

	issueProviderMock := mock_snyk.NewMockIssueProvider(ctrl)
	issueProviderMock.EXPECT().Issues().Return(snyk.IssuesByFile{})

	cmd.issueProvider = issueProviderMock

	// act
	res, err := cmd.Execute(t.Context())

	// assert
	assert.Error(t, err)
	assert.ErrorContains(t, err, "Failed to find autofix code action.")
	assert.Nil(t, res)

	var expectedMsg []any
	// Verify no workspace edit is sent to the client
	assert.Equal(t, expectedMsg, mockNotifier.SentMessages())
}
