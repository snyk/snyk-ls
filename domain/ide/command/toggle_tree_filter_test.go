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

package command

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

// setupToggleWorkspaceFolder registers a workspace with a single folder so the
// toggle command (which writes per-folder, workspace-wide) has a folder to act
// on. Returns the folder path for reading the resolved per-folder filters back.
func setupToggleWorkspaceFolder(t *testing.T, engine workflow.Engine) types.FilePath {
	t.Helper()
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	scanPersister := persistence.NewGitPersistenceProvider(engine.GetLogger(), engine.GetConfiguration())
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	resolver := testutil.DefaultConfigResolver(engine)
	folderPath := types.PathKey("dummy")
	w := workspace.New(engine.GetConfiguration(), engine.GetLogger(), performance.NewInstrumentor(), sc, nil, scanNotifier, notification.NewMockNotifier(), scanPersister, scanStateAggregator, featureflag.NewFakeService(), resolver, engine)
	folder := workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), folderPath, "dummy", sc, nil, scanNotifier, notification.NewMockNotifier(), scanPersister, scanStateAggregator, featureflag.NewFakeService(), resolver, engine)
	w.AddFolder(folder)
	config.SetWorkspace(engine.GetConfiguration(), w)
	return folderPath
}

// setupToggleWorkspaceFolders registers a workspace with one folder per given path.
func setupToggleWorkspaceFolders(t *testing.T, engine workflow.Engine, paths ...types.FilePath) {
	t.Helper()
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	scanPersister := persistence.NewGitPersistenceProvider(engine.GetLogger(), engine.GetConfiguration())
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	resolver := testutil.DefaultConfigResolver(engine)
	w := workspace.New(engine.GetConfiguration(), engine.GetLogger(), performance.NewInstrumentor(), sc, nil, scanNotifier, notification.NewMockNotifier(), scanPersister, scanStateAggregator, featureflag.NewFakeService(), resolver, engine)
	for _, p := range paths {
		folder := workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), p, string(p), sc, nil, scanNotifier, notification.NewMockNotifier(), scanPersister, scanStateAggregator, featureflag.NewFakeService(), resolver, engine)
		w.AddFolder(folder)
	}
	config.SetWorkspace(engine.GetConfiguration(), w)
}

func folderSeverityFilter(t *testing.T, engine workflow.Engine, folderPath types.FilePath) types.SeverityFilter {
	t.Helper()
	resolver := testutil.DefaultConfigResolver(engine)
	fc := config.GetFolderConfigFromEngine(engine, resolver, folderPath, engine.GetLogger())
	return resolver.FilterSeverityForFolder(fc)
}

func folderIssueViewOptions(t *testing.T, engine workflow.Engine, folderPath types.FilePath) types.IssueViewOptions {
	t.Helper()
	resolver := testutil.DefaultConfigResolver(engine)
	fc := config.GetFolderConfigFromEngine(engine, resolver, folderPath, engine.GetLogger())
	return resolver.IssueViewOptionsForFolder(fc)
}

func TestToggleTreeFilter_Execute_SeverityHigh_Disabled(t *testing.T) {
	engine := testutil.UnitTest(t)
	folderPath := setupToggleWorkspaceFolder(t, engine)
	types.SetSeverityFilterForFolder(engine.GetConfiguration(), folderPath, util.Ptr(types.NewSeverityFilter(true, true, true, true)))

	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"severity", "high", false},
		},
		engine: engine,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.Nil(t, result, "toggleTreeFilter should return nil; tree HTML is pushed via notification")

	filter := folderSeverityFilter(t, engine, folderPath)
	assert.True(t, filter.Critical)
	assert.False(t, filter.High, "high should be disabled for the folder")
	assert.True(t, filter.Medium)
	assert.True(t, filter.Low)
}

func TestToggleTreeFilter_Execute_SeverityMedium_Enabled(t *testing.T) {
	engine := testutil.UnitTest(t)
	folderPath := setupToggleWorkspaceFolder(t, engine)
	types.SetSeverityFilterForFolder(engine.GetConfiguration(), folderPath, util.Ptr(types.NewSeverityFilter(true, true, false, true)))

	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"severity", "medium", true},
		},
		engine: engine,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.Nil(t, result, "toggleTreeFilter should return nil; tree HTML is pushed via notification")

	filter := folderSeverityFilter(t, engine, folderPath)
	assert.True(t, filter.Medium, "medium should be enabled for the folder")
}

func TestToggleTreeFilter_Execute_IssueViewOpenIssues_Disabled(t *testing.T) {
	engine := testutil.UnitTest(t)
	folderPath := setupToggleWorkspaceFolder(t, engine)
	types.SetIssueViewOptionsForFolder(engine.GetConfiguration(), folderPath, util.Ptr(types.NewIssueViewOptions(true, true)))

	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"issueView", "openIssues", false},
		},
		engine: engine,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.Nil(t, result, "toggleTreeFilter should return nil; tree HTML is pushed via notification")

	options := folderIssueViewOptions(t, engine, folderPath)
	assert.False(t, options.OpenIssues, "open issues should be disabled for the folder")
	assert.True(t, options.IgnoredIssues)
}

func TestToggleTreeFilter_Execute_IssueViewIgnoredIssues_Enabled(t *testing.T) {
	engine := testutil.UnitTest(t)
	folderPath := setupToggleWorkspaceFolder(t, engine)
	types.SetIssueViewOptionsForFolder(engine.GetConfiguration(), folderPath, util.Ptr(types.NewIssueViewOptions(true, false)))

	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"issueView", "ignoredIssues", true},
		},
		engine: engine,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.Nil(t, result, "toggleTreeFilter should return nil; tree HTML is pushed via notification")

	options := folderIssueViewOptions(t, engine, folderPath)
	assert.True(t, options.IgnoredIssues, "ignored issues should be enabled for the folder")
}

func TestToggleTreeFilter_MixedFolders_TogglesOnlyClickedSeverity(t *testing.T) {
	// Two open folders with different severity filters. Clicking one severity in
	// the workspace-wide toolbar must set ONLY that severity on every folder and
	// leave each folder's other (legitimately differing) severities untouched.
	engine := testutil.UnitTest(t)
	pathA := types.PathKey("folderA")
	pathB := types.PathKey("folderB")
	setupToggleWorkspaceFolders(t, engine, pathA, pathB)
	types.SetSeverityFilterForFolder(engine.GetConfiguration(), pathA, util.Ptr(types.NewSeverityFilter(true, false, true, false)))
	types.SetSeverityFilterForFolder(engine.GetConfiguration(), pathB, util.Ptr(types.NewSeverityFilter(false, false, false, true)))

	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"severity", "high", true},
		},
		engine: engine,
	}
	_, err := cmd.Execute(t.Context())
	require.NoError(t, err)

	// Only High flips to true; Critical/Medium/Low keep each folder's own values.
	assert.Equal(t, types.NewSeverityFilter(true, true, true, false), folderSeverityFilter(t, engine, pathA), "folder A: only High changed")
	assert.Equal(t, types.NewSeverityFilter(false, true, false, true), folderSeverityFilter(t, engine, pathB), "folder B: only High changed")
}

func TestToggleTreeFilter_PerFolderValueOutranksGlobal(t *testing.T) {
	// The bug: severity filters were written user-global, but folder-scoped issue
	// filtering resolves folder value > remote > user-global, so an LDX-Sync
	// remote/folder default shadowed the user's choice. Writing per-folder
	// (UserFolderKey) must outrank the user-global value for the folder.
	engine := testutil.UnitTest(t)
	folderPath := setupToggleWorkspaceFolder(t, engine)

	// User-global says critical is enabled.
	config.SetSeverityFilterOnConfig(engine.GetConfiguration(), util.Ptr(types.NewSeverityFilter(true, true, true, true)), engine.GetLogger())
	// Per-folder says critical is disabled.
	types.SetSeverityFilterForFolder(engine.GetConfiguration(), folderPath, util.Ptr(types.NewSeverityFilter(false, true, true, true)))

	filter := folderSeverityFilter(t, engine, folderPath)
	assert.False(t, filter.Critical, "per-folder value must outrank the user-global value for the folder")
	assert.True(t, filter.High)
}

func TestToggleTreeFilter_Execute_MissingArgs_ReturnsError(t *testing.T) {
	engine := testutil.UnitTest(t)
	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{},
		},
		engine: engine,
	}

	_, err := cmd.Execute(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected 3 arguments")
}

func TestToggleTreeFilter_Execute_InvalidFilterType_ReturnsError(t *testing.T) {
	engine := testutil.UnitTest(t)
	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"unknown", "high", true},
		},
		engine: engine,
	}

	_, err := cmd.Execute(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown filter type")
}

func TestToggleTreeFilter_Execute_InvalidSeverityValue_ReturnsError(t *testing.T) {
	engine := testutil.UnitTest(t)
	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"severity", "extreme", true},
		},
		engine: engine,
	}

	_, err := cmd.Execute(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown severity value")
}

func TestToggleTreeFilter_Execute_ReturnsNil_NotHtml(t *testing.T) {
	engine := testutil.UnitTest(t)
	cmd := &toggleTreeFilter{
		command: types.CommandData{
			CommandId: types.ToggleTreeFilter,
			Arguments: []any{"severity", "low", false},
		},
		engine: engine,
	}

	result, err := cmd.Execute(t.Context())
	require.NoError(t, err)
	assert.Nil(t, result, "toggleTreeFilter should return nil; tree HTML is pushed via $/snyk.treeView notification")
}

func TestToggleTreeFilter_Command_ReturnsCommandData(t *testing.T) {
	cmdData := types.CommandData{CommandId: types.ToggleTreeFilter}
	cmd := &toggleTreeFilter{command: cmdData}
	assert.Equal(t, cmdData, cmd.Command())
}
