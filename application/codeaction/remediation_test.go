/*
 * © 2026 Snyk Limited
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
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/codeaction"
	"github.com/snyk/snyk-ls/application/watcher"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/mock_snyk"
	"github.com/snyk/snyk-ls/domain/snyk/remediation"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// fakeRemediationProvider is a test double that returns a pre-configured edit.
type fakeRemediationProvider struct {
	edit *types.WorkspaceEdit
	err  error
}

func (f *fakeRemediationProvider) Remediate(_ context.Context, _ remediation.RemediationRequest) (*types.WorkspaceEdit, error) {
	return f.edit, f.err
}

// buildFixableIssue constructs a Code issue with HasAIFix=true and a FindingId set.
func buildFixableIssue(findingId string) *snyk.Issue {
	return &snyk.Issue{
		FindingId: findingId,
		Product:   product.ProductCode,
		AdditionalData: snyk.CodeIssueData{
			HasAIFix: true,
		},
	}
}

func setupWithIssueAndProvider(
	t *testing.T,
	issue types.Issue,
	provider remediation.RemediationProvider,
) (*codeaction.CodeActionsService, types.CodeActionParams) {
	t.Helper()
	engine := testutil.UnitTest(t)
	r := exampleRange
	uriPath := documentUriExample
	path := uri.PathFromUri(uriPath)

	_, _ = workspaceutil.SetupWorkspace(t, engine, types.FilePath("/path/to"))

	ctrl := gomock.NewController(t)
	providerMock := mock_snyk.NewMockIssueProvider(ctrl)
	var issues []types.Issue
	if issue != nil {
		issues = []types.Issue{issue}
	}
	providerMock.EXPECT().IssuesForRange(path, converter.FromRange(r)).Return(issues).AnyTimes()

	service := codeaction.NewService(
		engine,
		providerMock,
		watcher.NewFileWatcher(),
		notification.NewMockNotifier(),
		featureflag.NewFakeService(),
		types.NewConfigResolver(engine.GetLogger()),
		provider,
	)

	params := types.CodeActionParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: uriPath},
		Range:        r,
		Context:      types.CodeActionContext{},
	}
	return service, params
}

func TestGetCodeActions_RemediationAgent_OfferedForFixableIssue(t *testing.T) {
	mockEdit := &types.WorkspaceEdit{
		Changes: map[string][]types.TextEdit{
			"file:///path/to/file": {
				{
					Range:   types.Range{Start: types.Position{Line: 1}, End: types.Position{Line: 2}},
					NewText: "fixed",
				},
			},
		},
	}
	fake := &fakeRemediationProvider{edit: mockEdit}
	issue := buildFixableIssue("finding-abc")

	service, params := setupWithIssueAndProvider(t, issue, fake)

	actions := service.GetCodeActions(params)

	// At least one action must have RemediationAgentQuickFix kind and a non-nil UUID (deferred).
	found := false
	for _, a := range actions {
		if a.Kind == types.RemediationAgentQuickFix {
			found = true
			assert.NotNil(t, a.Data, "deferred action must carry a UUID in Data")
			assert.Nil(t, a.Edit, "edit must be nil at list time (deferred)")
		}
	}
	assert.True(t, found, "expected at least one RemediationAgentQuickFix action")
}

func TestGetCodeActions_RemediationAgent_NilProvider_NoRemediationAction(t *testing.T) {
	issue := buildFixableIssue("finding-xyz")
	service, params := setupWithIssueAndProvider(t, issue, nil)

	actions := service.GetCodeActions(params)

	for _, a := range actions {
		assert.NotEqual(t, types.RemediationAgentQuickFix, a.Kind,
			"nil provider must not produce RemediationAgentQuickFix actions")
	}
}

func TestGetCodeActions_RemediationAgent_EmptyFindingId_NoAction(t *testing.T) {
	fake := &fakeRemediationProvider{edit: &types.WorkspaceEdit{}}
	// FindingId is empty — provider set, but no action should be generated.
	issue := buildFixableIssue("")

	service, params := setupWithIssueAndProvider(t, issue, fake)

	actions := service.GetCodeActions(params)

	for _, a := range actions {
		assert.NotEqual(t, types.RemediationAgentQuickFix, a.Kind,
			"empty FindingId must not produce RemediationAgentQuickFix actions")
	}
}

func TestResolveCodeAction_RemediationAgent_InvokesProvider(t *testing.T) {
	mockEdit := &types.WorkspaceEdit{
		Changes: map[string][]types.TextEdit{
			"file:///path/to/file": {
				{NewText: "provider-fixed"},
			},
		},
	}
	fake := &fakeRemediationProvider{edit: mockEdit}
	issue := buildFixableIssue("finding-resolve")

	service, params := setupWithIssueAndProvider(t, issue, fake)

	actions := service.GetCodeActions(params)

	// Find the Remy action.
	var remyAction *types.LSPCodeAction
	for i := range actions {
		if actions[i].Kind == types.RemediationAgentQuickFix {
			remyAction = &actions[i]
			break
		}
	}
	require.NotNil(t, remyAction, "expected RemediationAgentQuickFix action")

	resolved, err := service.ResolveCodeAction(*remyAction)
	require.NoError(t, err)
	require.NotNil(t, resolved.Edit, "resolved action must have an edit")
	// The converter transforms the key via uri.PathToUri; just verify the edit is populated.
	assert.Len(t, resolved.Edit.Changes, 1, "resolved edit must carry the provider's changes")
}

func TestGetCodeActions_RemediationAgent_DoesNotMutateIssueCodeActions(t *testing.T) {
	fake := &fakeRemediationProvider{edit: &types.WorkspaceEdit{}}
	issue := buildFixableIssue("finding-mutate")

	service, params := setupWithIssueAndProvider(t, issue, fake)

	// Record the number of code actions on the issue before calling GetCodeActions.
	beforeCount := len(issue.GetCodeActions())

	actions := service.GetCodeActions(params)

	// The issue's own CodeActions slice must be unchanged.
	assert.Equal(t, beforeCount, len(issue.GetCodeActions()),
		"GetCodeActions must not mutate issue.CodeActions")

	// The returned action list must still contain a RemediationAgentQuickFix.
	found := false
	for _, a := range actions {
		if a.Kind == types.RemediationAgentQuickFix {
			found = true
		}
	}
	assert.True(t, found, "expected RemediationAgentQuickFix in returned actions")
}
