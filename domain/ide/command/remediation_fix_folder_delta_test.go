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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/remediation"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// deltaFolder is a types.Folder that can also report its net-new set, which is
// the pair of interfaces the scoping path asserts against.
type deltaFolder struct {
	*mock_types.MockFolder
	netNew snyk.IssuesByFile
}

func (d *deltaFolder) GetDelta(_ product.Product) snyk.IssuesByFile { return d.netNew }

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

// scopedFixFolderFixture wires the real Remy provider to a recording runner over
// a real git repo, with a workspace holding folder at the repo path.
func scopedFixFolderFixture(t *testing.T, folder types.Folder, fn func(root string) error) (string, *recordingRunner, types.Workspace) {
	t.Helper()
	repo := initGitRepoForCmd(t)
	runner := &recordingRunner{fn: fn}

	ctrl := gomock.NewController(t)
	w := mock_types.NewMockWorkspace(ctrl)
	if folder != nil {
		w.EXPECT().Folders().Return([]types.Folder{folder}).AnyTimes()
	} else {
		w.EXPECT().Folders().Return(nil).AnyTimes()
	}
	return repo, runner, w
}

func newDeltaFolder(t *testing.T, path string, deltaEnabled, baseline bool, netNew snyk.IssuesByFile) *deltaFolder {
	t.Helper()
	mf := mock_types.NewMockFolder(gomock.NewController(t))
	mf.EXPECT().Path().Return(types.FilePath(path)).AnyTimes()
	mf.EXPECT().IsDeltaFindingsEnabled().Return(deltaEnabled).AnyTimes()
	mf.EXPECT().IsDeltaAppliedForProduct(product.ProductCode).Return(deltaEnabled && baseline).AnyTimes()
	return &deltaFolder{MockFolder: mf, netNew: netNew}
}

func executeScopedFixFolder(t *testing.T, args []any, runner *recordingRunner, w types.Workspace) (any, error) {
	t.Helper()
	p, ok := remediation.NewRemyProvider(nil, runner.run).(remediation.FolderRemediator)
	require.True(t, ok, "remyProvider must implement FolderRemediator")
	return newScopedFixFolderCmd(args, p, w).Execute(context.Background())
}

func modifyMain(root string) error {
	return os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nvar x = 2\n"), 0644)
}

// A single argument keeps the pre-scoping contract: every existing client runs unscoped.
func TestFixFolder_Execute_SingleArgument_RunsUnscoped(t *testing.T) {
	repo, runner, w := scopedFixFolderFixture(t, nil, nil)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	_, err := executeScopedFixFolder(t, []any{folderURI}, runner, w)

	require.NoError(t, err)
	assert.Equal(t, 1, runner.calls)
	assert.Empty(t, runner.findingIDs, "a single-argument call must not scope the run")
}

func TestFixFolder_Execute_ThreeArguments_Rejected(t *testing.T) {
	repo, runner, w := scopedFixFolderFixture(t, nil, nil)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	_, err := executeScopedFixFolder(t, []any{folderURI, folderURI, folderURI}, runner, w)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "got 3")
	assert.Zero(t, runner.calls)
}

func TestFixFolder_Execute_DeltaOff_RunsUnscoped(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folder := newDeltaFolder(t, repo, false, false, snyk.IssuesByFile{
		"main.go": {newIssue("finding-1")},
	})
	_, runner, w := scopedFixFolderFixture(t, folder, nil)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	_, err := executeScopedFixFolder(t, []any{folderURI, folderURI}, runner, w)

	require.NoError(t, err)
	assert.Equal(t, 1, runner.calls)
	assert.Empty(t, runner.findingIDs, "delta off must leave the run unscoped")
}

func TestFixFolder_Execute_DeltaOnNoBaseline_RunsUnscoped(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folder := newDeltaFolder(t, repo, true, false, snyk.IssuesByFile{
		"main.go": {newIssue("finding-1")},
	})
	_, runner, w := scopedFixFolderFixture(t, folder, nil)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	_, err := executeScopedFixFolder(t, []any{folderURI, folderURI}, runner, w)

	require.NoError(t, err)
	assert.Equal(t, 1, runner.calls)
	assert.Empty(t, runner.findingIDs, "a missing baseline must fail open to an unscoped run")
}

func TestFixFolder_Execute_DeltaOnWithBaseline_ScopesToNetNewFindingIDs(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folder := newDeltaFolder(t, repo, true, true, snyk.IssuesByFile{
		"main.go": {newIssue("finding-1"), newIssue("")},
		"util.go": {newIssue("finding-2")},
	})
	_, runner, w := scopedFixFolderFixture(t, folder, nil)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	_, err := executeScopedFixFolder(t, []any{folderURI, folderURI}, runner, w)

	require.NoError(t, err)
	assert.Equal(t, 1, runner.calls)
	assert.Equal(t, []string{"finding-1", "finding-2"}, runner.findingIDs,
		"the run must carry the net-new findings' native identifiers and drop the ones with none")
}

func TestFixFolder_Execute_DeltaOnEmptyNetNew_ReturnsEmptyWithoutInvokingRemy(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folder := newDeltaFolder(t, repo, true, true, snyk.IssuesByFile{})
	_, runner, w := scopedFixFolderFixture(t, folder, nil)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	result, err := executeScopedFixFolder(t, []any{folderURI, folderURI}, runner, w)

	require.NoError(t, err)
	assert.Zero(t, runner.calls, "an empty net-new set reaches remy as no filter, so the run must be skipped")
	ffr, ok := result.(types.FolderFixResult)
	require.True(t, ok)
	assert.Empty(t, ffr.Files)
	assert.NotNil(t, ffr.Files)
}

// An unregistered root cannot answer the delta questions, so the run fails open.
func TestFixFolder_Execute_UnregisteredRoot_RunsUnscoped(t *testing.T) {
	repo := initGitRepoForCmd(t)
	other := initGitRepoForCmd(t)
	folder := newDeltaFolder(t, other, true, true, snyk.IssuesByFile{
		"main.go": {newIssue("finding-1")},
	})
	_, runner, w := scopedFixFolderFixture(t, folder, nil)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	_, err := executeScopedFixFolder(t, []any{folderURI, folderURI}, runner, w)

	require.NoError(t, err)
	assert.Equal(t, 1, runner.calls)
	assert.Empty(t, runner.findingIDs, "a root matching no registered folder must run unscoped")
}

// A parent folder's net-new set belongs to a different folder, so containment
// must not be used to resolve the root.
func TestFixFolder_Execute_ParentFolderRegistered_RunsUnscoped(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folder := newDeltaFolder(t, filepath.Dir(repo), true, true, snyk.IssuesByFile{
		"main.go": {newIssue("parent-finding")},
	})
	_, runner, w := scopedFixFolderFixture(t, folder, nil)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	_, err := executeScopedFixFolder(t, []any{folderURI, folderURI}, runner, w)

	require.NoError(t, err)
	assert.Equal(t, 1, runner.calls)
	assert.Empty(t, runner.findingIDs, "only an exact path match may scope the run")
}

func TestFixFolder_Execute_NoWorkspace_RunsUnscoped(t *testing.T) {
	repo := initGitRepoForCmd(t)
	runner := &recordingRunner{}
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	_, err := executeScopedFixFolder(t, []any{folderURI, folderURI}, runner, nil)

	require.NoError(t, err)
	assert.Equal(t, 1, runner.calls)
	assert.Empty(t, runner.findingIDs)
}

func TestFixFolder_Execute_InvalidRootArgument_Rejected(t *testing.T) {
	repo, runner, w := scopedFixFolderFixture(t, nil, nil)
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	_, err := executeScopedFixFolder(t, []any{folderURI, 42}, runner, w)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "workspace root URI argument must be a non-empty string")
	assert.Zero(t, runner.calls)
}

// A scoped run that fixed only some requested ids still produced a usable patch.
func TestFixFolder_Execute_PartialFix_ReturnsChangedFiles(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folder := newDeltaFolder(t, repo, true, true, snyk.IssuesByFile{
		"main.go": {newIssue("finding-1"), newIssue("finding-2")},
	})
	partial := errors.New("selection: one or more requested issue ids were not fixed")
	_, runner, w := scopedFixFolderFixture(t, folder, func(root string) error {
		if err := modifyMain(root); err != nil {
			return err
		}
		return partial
	})
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	result, err := executeScopedFixFolder(t, []any{folderURI, folderURI}, runner, w)

	require.NoError(t, err, "a partly-fixed scoped run must not fail the command")
	ffr, ok := result.(types.FolderFixResult)
	require.True(t, ok)
	require.Len(t, ffr.Files, 1)
	assert.Contains(t, ffr.Files[0].Diff, "var x = 2")
}

// Pins the upstream wording: a reword must fail loudly rather than turn every
// partly-fixed run back into a failure.
func TestFixFolder_Execute_PartialFixSentinelWording(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folder := newDeltaFolder(t, repo, true, true, snyk.IssuesByFile{
		"main.go": {newIssue("finding-1")},
	})
	reworded := errors.New("selection: some requested issue ids remained unfixed")
	_, runner, w := scopedFixFolderFixture(t, folder, func(root string) error {
		if err := modifyMain(root); err != nil {
			return err
		}
		return reworded
	})
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	_, err := executeScopedFixFolder(t, []any{folderURI, folderURI}, runner, w)

	require.Error(t, err, "only the exact upstream message counts as a partial fix")
}

// An unscoped run requested nothing, so nothing can be partly fixed.
func TestFixFolder_Execute_PartialFixOnUnscopedRun_StillFails(t *testing.T) {
	partial := errors.New("selection: one or more requested issue ids were not fixed")
	repo, runner, w := scopedFixFolderFixture(t, nil, func(root string) error {
		if err := modifyMain(root); err != nil {
			return err
		}
		return partial
	})
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	_, err := executeScopedFixFolder(t, []any{folderURI}, runner, w)

	require.Error(t, err)
}

func TestFixFolder_Execute_OtherRunnerError_FailsCommand(t *testing.T) {
	repo := initGitRepoForCmd(t)
	folder := newDeltaFolder(t, repo, true, true, snyk.IssuesByFile{
		"main.go": {newIssue("finding-1")},
	})
	boom := errors.New("remy exploded")
	_, runner, w := scopedFixFolderFixture(t, folder, func(_ string) error { return boom })
	folderURI := string(uri.PathToUri(types.FilePath(repo)))

	_, err := executeScopedFixFolder(t, []any{folderURI, folderURI}, runner, w)

	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
}
