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

package command_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/mock_snyk"
	"github.com/snyk/snyk-ls/domain/snyk/remediation"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// deltaFolder is the pair of interfaces the concrete workspace folder satisfies
// and the scoping path asserts against.
type deltaFolder struct {
	*mock_types.MockFolder
	*mock_snyk.MockFilteringIssueProvider
}

// recordingRunner captures the finding ids a fix run was scoped to and applies fn.
type recordingRunner struct {
	calls      int
	findingIDs []string
	fn         func(root string) error
}

func (r *recordingRunner) run(_ context.Context, _ workflow.Engine, root string, findingIDs []string) error {
	r.calls++
	r.findingIDs = findingIDs
	if r.fn == nil {
		return nil
	}
	return r.fn(root)
}

func newIssue(findingID string) types.Issue {
	return &snyk.Issue{FindingId: findingID, Product: product.ProductCode}
}

// newDeltaFolder builds a folder whose cache holds cached and whose display
// filter keeps shown.
func newDeltaFolder(t *testing.T, path string, deltaEnabled, baseline bool, cached, shown snyk.IssuesByFile) *deltaFolder {
	t.Helper()
	ctrl := gomock.NewController(t)
	displayable := map[product.FilterableIssueType]bool{product.FilterableIssueTypeCodeSecurity: true}
	mf := mock_types.NewMockFolder(ctrl)
	mf.EXPECT().Path().Return(types.FilePath(path)).AnyTimes()
	mf.EXPECT().IsDeltaFindingsEnabled().Return(deltaEnabled).AnyTimes()
	mf.EXPECT().IsDeltaAppliedForProduct(product.ProductCode).Return(deltaEnabled && baseline).AnyTimes()
	mf.EXPECT().DisplayableIssueTypes().Return(displayable).AnyTimes()
	fip := mock_snyk.NewMockFilteringIssueProvider(ctrl)
	fip.EXPECT().Issues().Return(cached).AnyTimes()
	fip.EXPECT().FilterIssues(cached, displayable).Return(shown).AnyTimes()
	return &deltaFolder{MockFolder: mf, MockFilteringIssueProvider: fip}
}

// scopingFolder is a delta-applied folder that shows exactly the issues it holds.
func scopingFolder(t *testing.T, path string, issues snyk.IssuesByFile) *deltaFolder {
	t.Helper()
	return newDeltaFolder(t, path, true, true, issues, issues)
}

func workspaceWith(t *testing.T, folders ...types.Folder) types.Workspace {
	t.Helper()
	w := mock_types.NewMockWorkspace(gomock.NewController(t))
	w.EXPECT().Folders().Return(folders).AnyTimes()
	return w
}

func executeScopedFixFolder(t *testing.T, args []any, runner *recordingRunner, w types.Workspace) (any, error) {
	t.Helper()
	p, ok := remediation.NewRemyProvider(nil, runner.run).(remediation.FolderRemediator)
	require.True(t, ok, "remyProvider must implement FolderRemediator")
	return newScopedFixFolderCmd(args, p, w).Execute(context.Background())
}

func repoURI(repo string) string {
	return string(uri.PathToUri(types.FilePath(repo)))
}

func modifyMain(root string) error {
	return os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nvar x = 2\n"), 0644)
}

const partialFixError = "selection: one or more requested issue ids were not fixed"

func TestFixFolder_Execute_RunsUnscoped(t *testing.T) {
	netNew := snyk.IssuesByFile{"main.go": {newIssue("finding-1")}}
	tests := []struct {
		name      string
		singleArg bool
		workspace func(t *testing.T, repo string) types.Workspace
	}{
		{
			// A single argument runs unscoped.
			name:      "single argument",
			singleArg: true,
			workspace: func(t *testing.T, repo string) types.Workspace {
				t.Helper()
				return workspaceWith(t, scopingFolder(t, repo, netNew))
			},
		},
		{
			name: "delta off",
			workspace: func(t *testing.T, repo string) types.Workspace {
				t.Helper()
				return workspaceWith(t, newDeltaFolder(t, repo, false, false, netNew, netNew))
			},
		},
		{
			name: "delta on without a baseline",
			workspace: func(t *testing.T, repo string) types.Workspace {
				t.Helper()
				return workspaceWith(t, newDeltaFolder(t, repo, true, false, netNew, netNew))
			},
		},
		{
			name: "root matches no registered folder",
			workspace: func(t *testing.T, _ string) types.Workspace {
				t.Helper()
				return workspaceWith(t, scopingFolder(t, initGitRepoForCmd(t), netNew))
			},
		},
		{
			// A parent folder's net-new set belongs to a different folder.
			name: "only a parent folder is registered",
			workspace: func(t *testing.T, repo string) types.Workspace {
				t.Helper()
				return workspaceWith(t, scopingFolder(t, filepath.Dir(repo), netNew))
			},
		},
		{
			name:      "no workspace",
			workspace: func(*testing.T, string) types.Workspace { return nil },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := initGitRepoForCmd(t)
			runner := &recordingRunner{}
			args := []any{repoURI(repo), repoURI(repo)}
			if tt.singleArg {
				args = args[:1]
			}

			_, err := executeScopedFixFolder(t, args, runner, tt.workspace(t, repo))

			require.NoError(t, err)
			assert.Equal(t, 1, runner.calls)
			assert.Empty(t, runner.findingIDs)
		})
	}
}

func TestFixFolder_Execute_ThreeArguments_Rejected(t *testing.T) {
	repo := initGitRepoForCmd(t)
	runner := &recordingRunner{}

	_, err := executeScopedFixFolder(t, []any{repoURI(repo), repoURI(repo), repoURI(repo)}, runner, workspaceWith(t))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "got 3")
	assert.Zero(t, runner.calls)
}

func TestFixFolder_Execute_InvalidRootArgument_Rejected(t *testing.T) {
	repo := initGitRepoForCmd(t)
	runner := &recordingRunner{}

	_, err := executeScopedFixFolder(t, []any{repoURI(repo), 42}, runner, workspaceWith(t))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "workspace root URI argument must be a non-empty string")
	assert.Zero(t, runner.calls)
}

func TestFixFolder_Execute_DeltaOnWithBaseline_ScopesToNetNewFindingIDs(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folder := scopingFolder(t, repo, snyk.IssuesByFile{
		"main.go":      {newIssue("finding-1"), newIssue(""), newIssue("finding-2")},
		"util.go":      {newIssue("finding-2")},
		"package.json": {&snyk.Issue{FindingId: "oss-finding", Product: product.ProductOpenSource}},
	})
	runner := &recordingRunner{}

	_, err := executeScopedFixFolder(t, []any{repoURI(repo), repoURI(repo)}, runner, workspaceWith(t, folder))

	require.NoError(t, err)
	assert.Equal(t, 1, runner.calls)
	assert.Equal(t, []string{"finding-1", "finding-2"}, runner.findingIDs,
		"the run must carry each net-new Snyk Code finding id once and drop issues with none")
}

func TestFixFolder_Execute_HiddenNetNewFinding_LeftOutOfScope(t *testing.T) {
	repo := initGitRepoForCmd(t)
	shown := newIssue("shown")
	ignored := &snyk.Issue{FindingId: "ignored", Product: product.ProductCode, IsIgnored: true}
	folder := newDeltaFolder(t, repo, true, true,
		snyk.IssuesByFile{"main.go": {shown, ignored}},
		snyk.IssuesByFile{"main.go": {shown}})
	runner := &recordingRunner{}

	_, err := executeScopedFixFolder(t, []any{repoURI(repo), repoURI(repo)}, runner, workspaceWith(t, folder))

	require.NoError(t, err)
	assert.Equal(t, []string{"shown"}, runner.findingIDs, "a finding the developer was not shown must not be fixed")
}

func TestFixFolder_Execute_DeltaOnEmptyNetNew_ReturnsEmptyWithoutInvokingRemy(t *testing.T) {
	repo := initGitRepoForCmd(t)
	runner := &recordingRunner{}

	result, err := executeScopedFixFolder(t, []any{repoURI(repo), repoURI(repo)}, runner,
		workspaceWith(t, scopingFolder(t, repo, snyk.IssuesByFile{})))

	require.NoError(t, err)
	assert.Zero(t, runner.calls, "an empty net-new set reaches remy as no filter, so the run must be skipped")
	ffr, ok := result.(types.FolderFixResult)
	require.True(t, ok)
	assert.Empty(t, ffr.Files)
	assert.NotNil(t, ffr.Files)
}

// A scoped run that fixed only some requested ids still produced a usable patch.
func TestFixFolder_Execute_PartialFix_ReturnsChangedFiles(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folder := scopingFolder(t, repo, snyk.IssuesByFile{
		"main.go": {newIssue("finding-1"), newIssue("finding-2")},
	})
	runner := &recordingRunner{fn: func(root string) error {
		if err := modifyMain(root); err != nil {
			return err
		}
		return errors.New(partialFixError)
	}}

	result, err := executeScopedFixFolder(t, []any{repoURI(repo), repoURI(repo)}, runner, workspaceWith(t, folder))

	require.NoError(t, err, "a partly-fixed scoped run must not fail the command")
	ffr, ok := result.(types.FolderFixResult)
	require.True(t, ok)
	require.Len(t, ffr.Files, 1)
	assert.Contains(t, ffr.Files[0].Diff, "var x = 2")
}

func TestFixFolder_Execute_PartialFixWithNoChanges_ReturnsEmptyFiles(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folder := scopingFolder(t, repo, snyk.IssuesByFile{"main.go": {newIssue("finding-1")}})
	runner := &recordingRunner{fn: func(string) error { return errors.New(partialFixError) }}

	result, err := executeScopedFixFolder(t, []any{repoURI(repo), repoURI(repo)}, runner, workspaceWith(t, folder))

	require.NoError(t, err, "a scoped run that fixed nothing must not fail the command")
	ffr, ok := result.(types.FolderFixResult)
	require.True(t, ok)
	encoded, err := json.Marshal(ffr)
	require.NoError(t, err)
	assert.JSONEq(t, `{"files":[]}`, string(encoded))
}

// Pins the upstream wording: a reword must fail loudly rather than turn every
// partly-fixed run back into a failure.
func TestFixFolder_Execute_PartialFixSentinelWording(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folder := scopingFolder(t, repo, snyk.IssuesByFile{"main.go": {newIssue("finding-1")}})
	runner := &recordingRunner{fn: func(root string) error {
		if err := modifyMain(root); err != nil {
			return err
		}
		return errors.New("selection: some requested issue ids remained unfixed")
	}}

	_, err := executeScopedFixFolder(t, []any{repoURI(repo), repoURI(repo)}, runner, workspaceWith(t, folder))

	require.Error(t, err, "only the exact upstream message counts as a partial fix")
}

// An unscoped run requested nothing, so nothing can be partly fixed.
func TestFixFolder_Execute_PartialFixOnUnscopedRun_StillFails(t *testing.T) {
	repo := initGitRepoForCmd(t)
	runner := &recordingRunner{fn: func(root string) error {
		if err := modifyMain(root); err != nil {
			return err
		}
		return errors.New(partialFixError)
	}}

	_, err := executeScopedFixFolder(t, []any{repoURI(repo)}, runner, workspaceWith(t))

	require.Error(t, err)
}

func TestFixFolder_Execute_OtherRunnerError_FailsCommand(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folder := scopingFolder(t, repo, snyk.IssuesByFile{"main.go": {newIssue("finding-1")}})
	boom := errors.New("remy exploded")
	runner := &recordingRunner{fn: func(string) error { return boom }}

	_, err := executeScopedFixFolder(t, []any{repoURI(repo), repoURI(repo)}, runner, workspaceWith(t, folder))

	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
}
