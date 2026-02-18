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
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// Test_SmokeTreeView verifies the server-driven HTML tree view end-to-end:
// 1. $/snyk.treeView notification is sent after scan with valid HTML and issue data
// 2. snyk.getTreeView command returns HTML on demand
// 3. snyk.toggleTreeFilter command updates filter and returns re-rendered HTML
// 4. snyk.getTreeViewIssueChunk command returns paginated issue chunk
func Test_SmokeTreeView(t *testing.T) {
	c := testutil.SmokeTest(t, "")
	loc, jsonRPCRecorder := setupServer(t, c)
	c.SetSnykCodeEnabled(true)
	c.SetSnykOssEnabled(true)
	c.SetSnykIacEnabled(false)
	di.Init()

	cloneTargetDir := setupRepoAndInitialize(t, testsupport.NodejsGoof, "0336589", "package.json", loc, c)
	cloneTargetDirString := string(cloneTargetDir)

	waitForScan(t, cloneTargetDirString, c)

	// --- 1. Verify $/snyk.treeView notification received after scan ---
	t.Run("tree view notification received after scan", func(t *testing.T) {
		require.Eventually(t, func() bool {
			notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.treeView")
			return len(notifications) > 0
		}, maxIntegTestDuration, 100*time.Millisecond, "expected $/snyk.treeView notification after scan")

		notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.treeView")
		lastNotification := notifications[len(notifications)-1]
		var treeView types.TreeView
		require.NoError(t, json.Unmarshal([]byte(lastNotification.ParamString()), &treeView))

		assert.Contains(t, treeView.TreeViewHtml, "<!DOCTYPE html>")
		assert.Contains(t, treeView.TreeViewHtml, "tree-container")
		assert.Contains(t, treeView.TreeViewHtml, "${ideScript}")
		assert.Contains(t, treeView.TreeViewHtml, "filter-btn")
		assert.Greater(t, treeView.TotalIssues, 0, "expected TotalIssues > 0 after scan")
	})

	// --- 2. snyk.getTreeView returns HTML on demand ---
	t.Run("getTreeView command returns HTML", func(t *testing.T) {
		response, err := loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
			Command: types.GetTreeView,
		})
		require.NoError(t, err)

		var htmlResult string
		require.NoError(t, response.UnmarshalResult(&htmlResult))
		assert.Contains(t, htmlResult, "<!DOCTYPE html>")
		assert.Contains(t, htmlResult, "tree-container")
		assert.Contains(t, htmlResult, "tree-node")
		assert.Contains(t, htmlResult, "Snyk Code", "expected Snyk Code product in tree")
		assert.Contains(t, htmlResult, "app.js", "expected code file in tree")
	})

	// --- 3. snyk.toggleTreeFilter toggles severity and triggers tree view notification ---
	t.Run("toggleTreeFilter disables low severity", func(t *testing.T) {
		notificationsBefore := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.treeView")
		countBefore := len(notificationsBefore)

		response, err := loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
			Command:   types.ToggleTreeFilter,
			Arguments: []any{"severity", "low", false},
		})
		require.NoError(t, err)

		// Command should return nil — tree HTML arrives via $/snyk.treeView notification
		var result any
		require.NoError(t, response.UnmarshalResult(&result))
		assert.Nil(t, result, "toggleTreeFilter should return nil; tree is pushed via notification")

		// Wait for a new $/snyk.treeView notification with the filter applied
		require.Eventually(t, func() bool {
			return len(jsonRPCRecorder.FindNotificationsByMethod("$/snyk.treeView")) > countBefore
		}, 5*time.Second, 100*time.Millisecond, "expected new $/snyk.treeView notification after filter toggle")

		notifications := jsonRPCRecorder.FindNotificationsByMethod("$/snyk.treeView")
		lastNotification := notifications[len(notifications)-1]
		var treeView types.TreeView
		require.NoError(t, json.Unmarshal([]byte(lastNotification.ParamString()), &treeView))
		assert.Contains(t, treeView.TreeViewHtml, `data-filter-value="low" class="filter-btn filter-btn-icon"`,
			"low severity button should not have filter-active class")

		// Re-enable low severity for clean state
		_, err = loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
			Command:   types.ToggleTreeFilter,
			Arguments: []any{"severity", "low", true},
		})
		require.NoError(t, err)
	})

	// --- 4. snyk.getTreeViewIssueChunk returns issue chunk for a code file ---
	t.Run("getTreeViewIssueChunk returns issues for app.js", func(t *testing.T) {
		appJsPath := filepath.Join(cloneTargetDirString, "app.js")
		response, err := loc.Client.Call(t.Context(), "workspace/executeCommand", sglsp.ExecuteCommandParams{
			Command: types.GetTreeViewIssueChunk,
			Arguments: []any{
				map[string]any{
					"filePath": appJsPath,
					"product":  "Snyk Code",
					"range":    map[string]any{"start": 0, "end": 50},
				},
			},
		})
		require.NoError(t, err)

		var chunkResult types.GetTreeViewIssueChunkResult
		require.NoError(t, response.UnmarshalResult(&chunkResult))
		assert.Greater(t, chunkResult.TotalFileIssues, 0, "expected code issues for app.js")
		assert.NotEmpty(t, chunkResult.IssueNodesHtml, "expected issue HTML fragment")
		assert.Contains(t, chunkResult.IssueNodesHtml, "tree-node-issue")
	})

	waitForDeltaScan(t, di.ScanStateAggregator())
}
