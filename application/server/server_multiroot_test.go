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

package server

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// contentRootForFile returns the ContentRoot published for the given file's
// most recent non-empty publishDiagnostics notification, or "" if none is found.
func contentRootForFile(t *testing.T, jsonRPCRecorder *testsupport.JsonRPCRecorder, file types.FilePath) types.FilePath {
	t.Helper()
	want := uri.PathToUri(file)
	var root types.FilePath
	for _, n := range jsonRPCRecorder.FindNotificationsByMethod("textDocument/publishDiagnostics") {
		var params types.PublishDiagnosticsParams
		if n.UnmarshalParams(&params) != nil {
			continue
		}
		if params.URI != want || len(params.Diagnostics) == 0 {
			continue
		}
		root = params.Diagnostics[0].Data.ContentRoot
	}
	return root
}

// ACC-005: in a workspace with more than one root, every finding's ContentRoot
// must equal the canonical registered root it physically belongs to. A finding
// in the second root must NOT be mis-attributed to the first root, even when the
// finding's own ContentRoot reports the wrong root (as happens today when a
// sub-path is scanned).
func TestFinding_RootAttribution_MultiRoot(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	loc, jsonRPCRecorder, _ := setupServer(t, engine, tokenService)

	_, err := loc.Client.Call(t.Context(), "initialize", nil)
	require.NoError(t, err)
	engine.GetConfiguration().Set(types.SettingIsLspInitialized, true)

	rootA := types.FilePath(t.TempDir())
	rootB := types.FilePath(t.TempDir())
	fileA := types.FilePath(filepath.Join(string(rootA), "a.go"))
	fileB := types.FilePath(filepath.Join(string(rootB), "b.go"))

	newFolder := func(root types.FilePath, name string) *workspace.Folder {
		return workspace.NewFolder(
			engine.GetConfiguration(), engine.GetLogger(), root, name,
			di.Scanner(), di.HoverService(), di.ScanNotifier(), di.Notifier(),
			di.ScanPersister(), di.ScanStateAggregator(), featureflag.NewFakeService(),
			di.ConfigResolver(), engine,
		)
	}
	folderA := newFolder(rootA, "rootA")
	folderB := newFolder(rootB, "rootB")
	ws := config.GetWorkspace(engine.GetConfiguration())
	ws.AddFolder(folderA)
	ws.AddFolder(folderB)

	// Both findings carry rootA as their own ContentRoot, simulating the
	// mis-attribution bug where a finding reports the first/wrong root. Each
	// folder must publish the finding with its own canonical registered root.
	issueA := testutil.NewMockIssue("issueA", fileA)
	issueA.ContentRoot = rootA
	issueB := testutil.NewMockIssue("issueB", fileB)
	issueB.ContentRoot = rootA // deliberately wrong: pretends to belong to rootA

	folderA.ProcessResults(t.Context(), types.ScanData{
		Product:           product.ProductOpenSource,
		Issues:            []types.Issue{issueA},
		UpdateGlobalCache: true,
	})
	folderB.ProcessResults(t.Context(), types.ScanData{
		Product:           product.ProductOpenSource,
		Issues:            []types.Issue{issueB},
		UpdateGlobalCache: true,
	})

	require.Eventually(t, func() bool {
		return contentRootForFile(t, jsonRPCRecorder, fileA) != "" &&
			contentRootForFile(t, jsonRPCRecorder, fileB) != ""
	}, 5*time.Second, 10*time.Millisecond, "expected diagnostics published for both roots")

	assert.Equal(t, rootA, contentRootForFile(t, jsonRPCRecorder, fileA),
		"finding in rootA must be attributed to rootA")
	assert.Equal(t, rootB, contentRootForFile(t, jsonRPCRecorder, fileB),
		"finding in rootB must be attributed to its own canonical root, not the first root")
}
