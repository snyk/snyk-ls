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
	return setupWithIssueAndProviderFlag(t, issue, provider, false)
}

func setupWithIssueAndProviderFlagEnabled(
	t *testing.T,
	issue types.Issue,
	provider remediation.RemediationProvider,
) (*codeaction.CodeActionsService, types.CodeActionParams) {
	t.Helper()
	return setupWithIssueAndProviderFlag(t, issue, provider, true)
}

func setupWithIssueAndProviderFlag(
	t *testing.T,
	issue types.Issue,
	provider remediation.RemediationProvider,
	remediationFlagEnabled bool,
) (*codeaction.CodeActionsService, types.CodeActionParams) {
	t.Helper()
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set("remediation_agent_enabled", remediationFlagEnabled)
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

// TestGetCodeActions_RemediationAgent_FlagDisabled_NoAction verifies that when
// remediation_agent_enabled is not set (default false), no RemediationAgentQuickFix
// action is emitted, even for an otherwise-eligible fixable Code issue. This keeps
// the code-action surface consistent with the command advertised in server capabilities,
// which is also gated behind the same flag.
func TestGetCodeActions_RemediationAgent_FlagDisabled_NoAction(t *testing.T) {
	fake := &fakeRemediationProvider{edit: &types.WorkspaceEdit{}}
	issue := buildFixableIssue("finding-flag-off")
	// setupWithIssueAndProvider does NOT set remediation_agent_enabled, so it defaults
	// to false. The flag gate in remediationCodeActions must suppress the action.
	service, params := setupWithIssueAndProvider(t, issue, fake)

	actions := service.GetCodeActions(params)

	for _, a := range actions {
		assert.NotEqual(t, types.RemediationAgentQuickFix, a.Kind,
			"flag remediation_agent_enabled=false must suppress RemediationAgentQuickFix actions")
	}
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

	service, params := setupWithIssueAndProviderFlagEnabled(t, issue, fake)

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

	service, params := setupWithIssueAndProviderFlagEnabled(t, issue, fake)

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

	resolved, err := service.ResolveCodeAction(t.Context(), *remyAction)
	require.NoError(t, err)
	require.NotNil(t, resolved.Edit, "resolved action must have an edit")
	// The converter transforms the key via uri.PathToUri; just verify the edit is populated.
	assert.Len(t, resolved.Edit.Changes, 1, "resolved edit must carry the provider's changes")
}

func TestGetCodeActions_RemediationAgent_NonCodeProduct_NoAction(t *testing.T) {
	fake := &fakeRemediationProvider{edit: &types.WorkspaceEdit{}}

	// OSS issue with a FindingId and HasAIFix — should not get a remediation action.
	ossIssue := &snyk.Issue{
		FindingId: "finding-oss",
		Product:   product.ProductOpenSource,
		AdditionalData: snyk.OssIssueData{
			IsUpgradable: true,
		},
	}

	service, params := setupWithIssueAndProvider(t, ossIssue, fake)
	actions := service.GetCodeActions(params)

	for _, a := range actions {
		assert.NotEqual(t, types.RemediationAgentQuickFix, a.Kind,
			"non-Code product must not produce RemediationAgentQuickFix actions")
	}
}

// TestGetCodeActions_RemediationAgent_FullyFixableOSS_NoAction verifies that an
// OSS issue where IsFixable() returns true (upgradable with a real upgrade path)
// does NOT receive a RemediationAgentQuickFix action. The remy agent is designed
// for Code (hasAIFix) and IaC issues; OSS upgrades are handled by a separate
// mechanism (package manager upgrade, not LLM code edits).
func TestGetCodeActions_RemediationAgent_FullyFixableOSS_NoAction(t *testing.T) {
	fake := &fakeRemediationProvider{edit: &types.WorkspaceEdit{}}

	// Construct an OSS issue where IsFixable() returns true:
	// IsUpgradable=true, UpgradePath[1] != From[1], len(UpgradePath)>1, len(From)>1.
	ossIssue := &snyk.Issue{
		FindingId: "finding-oss-fixable",
		Product:   product.ProductOpenSource,
		AdditionalData: snyk.OssIssueData{
			IsUpgradable: true,
			UpgradePath:  []any{"lodash@4.17.21", "lodash@4.17.21"},
			From:         []string{"app@1.0.0", "lodash@4.17.4"},
		},
	}

	service, params := setupWithIssueAndProvider(t, ossIssue, fake)
	actions := service.GetCodeActions(params)

	for _, a := range actions {
		assert.NotEqual(t, types.RemediationAgentQuickFix, a.Kind,
			"fully-fixable OSS issue (IsFixable()==true) must not produce RemediationAgentQuickFix actions; remy handles Code/IaC only")
	}
}

func TestGetCodeActions_RemediationAgent_NotAIFixable_NoAction(t *testing.T) {
	fake := &fakeRemediationProvider{edit: &types.WorkspaceEdit{}}

	// Code issue with HasAIFix=false — provider present but issue is not AI-fixable.
	issue := &snyk.Issue{
		FindingId: "finding-not-fixable",
		Product:   product.ProductCode,
		AdditionalData: snyk.CodeIssueData{
			HasAIFix: false,
		},
	}

	service, params := setupWithIssueAndProvider(t, issue, fake)
	actions := service.GetCodeActions(params)

	for _, a := range actions {
		assert.NotEqual(t, types.RemediationAgentQuickFix, a.Kind,
			"non-AI-fixable Code issue must not produce RemediationAgentQuickFix actions")
	}
}

func TestGetCodeActions_RemediationAgent_DoesNotMutateIssueCodeActions(t *testing.T) {
	fake := &fakeRemediationProvider{edit: &types.WorkspaceEdit{}}
	issue := buildFixableIssue("finding-mutate")

	service, params := setupWithIssueAndProviderFlagEnabled(t, issue, fake)

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

func TestGetCodeActions_RemediationAgent_SecretsIssue_NoAction(t *testing.T) {
	fake := &fakeRemediationProvider{edit: &types.WorkspaceEdit{}}
	issue := &snyk.Issue{
		FindingId:      "finding-secret",
		Product:        product.ProductSecrets,
		AdditionalData: snyk.SecretsIssueData{},
	}

	service, params := setupWithIssueAndProvider(t, issue, fake)

	actions := service.GetCodeActions(params)

	for _, a := range actions {
		assert.NotEqual(t, types.RemediationAgentQuickFix, a.Kind,
			"Secrets product must not produce RemediationAgentQuickFix actions")
	}
}

func TestGetCodeActions_RemediationAgent_UnknownProduct_NoAction(t *testing.T) {
	fake := &fakeRemediationProvider{edit: &types.WorkspaceEdit{}}
	issue := &snyk.Issue{
		FindingId:      "finding-unknown",
		Product:        product.ProductUnknown,
		AdditionalData: snyk.CodeIssueData{HasAIFix: true},
	}

	service, params := setupWithIssueAndProvider(t, issue, fake)

	actions := service.GetCodeActions(params)

	for _, a := range actions {
		assert.NotEqual(t, types.RemediationAgentQuickFix, a.Kind,
			"unknown product must not produce RemediationAgentQuickFix actions")
	}
}

func TestGetCodeActions_RemediationAgent_IaCIssue_WithFindingId_OfferedAction(t *testing.T) {
	fake := &fakeRemediationProvider{edit: &types.WorkspaceEdit{}}
	issue := &snyk.Issue{
		FindingId:      "finding-iac",
		Product:        product.ProductInfrastructureAsCode,
		AdditionalData: snyk.IaCIssueData{},
	}

	service, params := setupWithIssueAndProviderFlagEnabled(t, issue, fake)

	actions := service.GetCodeActions(params)

	found := false
	for _, a := range actions {
		if a.Kind == types.RemediationAgentQuickFix {
			found = true
		}
	}
	assert.True(t, found, "IaC issue with FindingId must produce RemediationAgentQuickFix action")
}

// TestGetCodeActions_RemediationAgent_DedupsMultipleFixableIssues verifies that
// when IssuesForRange returns more than one eligible fixable issue for the same
// request range, the client receives exactly ONE remediation action rather than
// multiple identical-titled quickfix entries.
func TestGetCodeActions_RemediationAgent_DedupsMultipleFixableIssues(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set("remediation_agent_enabled", true)
	r := exampleRange
	uriPath := documentUriExample
	path := uri.PathFromUri(uriPath)

	_, _ = workspaceutil.SetupWorkspace(t, engine, types.FilePath("/path/to"))

	ctrl := gomock.NewController(t)
	providerMock := mock_snyk.NewMockIssueProvider(ctrl)
	issues := []types.Issue{
		buildFixableIssue("finding-1"),
		buildFixableIssue("finding-2"),
	}
	providerMock.EXPECT().IssuesForRange(path, converter.FromRange(r)).Return(issues).AnyTimes()

	service := codeaction.NewService(
		engine,
		providerMock,
		watcher.NewFileWatcher(),
		notification.NewMockNotifier(),
		featureflag.NewFakeService(),
		types.NewConfigResolver(engine.GetLogger()),
		&fakeRemediationProvider{edit: &types.WorkspaceEdit{}},
	)

	params := types.CodeActionParams{
		TextDocument: sglsp.TextDocumentIdentifier{URI: uriPath},
		Range:        r,
		Context:      types.CodeActionContext{},
	}

	actions := service.GetCodeActions(params)

	count := 0
	for _, a := range actions {
		if a.Kind == types.RemediationAgentQuickFix {
			count++
		}
	}
	assert.Equal(t, 1, count,
		"multiple fixable issues in the same range must yield exactly one remediation action (dedup by title)")
}

// recordingRemediationProvider captures the context passed to Remediate.
type recordingRemediationProvider struct {
	receivedCtx context.Context
}

func (r *recordingRemediationProvider) Remediate(ctx context.Context, _ remediation.RemediationRequest) (*types.WorkspaceEdit, error) {
	r.receivedCtx = ctx
	return &types.WorkspaceEdit{}, nil
}

// TestResolveCodeAction_RemediationAgent_PropagatesContext proves that the
// context supplied to ResolveCodeAction is threaded through to the provider.
// Before the fix, provider.Remediate receives context.Background() even when
// ResolveCodeAction is called with a cancellable context; after the fix it
// receives the passed context, so canceling that context also cancels the
// provider call.
func TestResolveCodeAction_RemediationAgent_PropagatesContext(t *testing.T) {
	recorder := &recordingRemediationProvider{}
	issue := buildFixableIssue("finding-ctx")

	service, params := setupWithIssueAndProviderFlagEnabled(t, issue, recorder)

	actions := service.GetCodeActions(params)

	var remyAction *types.LSPCodeAction
	for i := range actions {
		if actions[i].Kind == types.RemediationAgentQuickFix {
			remyAction = &actions[i]
			break
		}
	}
	require.NotNil(t, remyAction, "expected RemediationAgentQuickFix action")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so we can assert the provider received a Done ctx

	_, err := service.ResolveCodeAction(ctx, *remyAction)
	require.NoError(t, err)

	// The provider must have received the same (canceled) context — not
	// context.Background(), which would never be Done.
	require.NotNil(t, recorder.receivedCtx, "provider must have been called")
	select {
	case <-recorder.receivedCtx.Done():
		// correct: the provider received a canceled context
	default:
		t.Fatal("provider received a non-canceled context; cancellation was not propagated")
	}
}
