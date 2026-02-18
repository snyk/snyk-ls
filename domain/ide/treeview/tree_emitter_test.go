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

package treeview

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestTreeViewEmitter_Emit_SendsNotification(t *testing.T) {
	c := testutil.UnitTest(t)
	notif := notification.NewNotifier()

	var receivedPayload any
	notif.CreateListener(func(params any) {
		receivedPayload = params
	})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeViewEmitter(c, notif)
	require.NoError(t, err)

	filePath := types.FilePath("/project/main.go")
	issue := testutil.NewMockIssue("issue-1", filePath)
	issue.Product = product.ProductOpenSource

	folderData := []FolderData{
		{
			FolderPath:          "/project",
			FolderName:          "project",
			SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeOpenSource: true},
			AllIssues:           snyk.IssuesByFile{filePath: {issue}},
			FilteredIssues:      snyk.IssuesByFile{filePath: {issue}},
		},
	}

	emitter.Emit(folderData)

	// Allow time for async notification delivery
	assert.Eventually(t, func() bool {
		return receivedPayload != nil
	}, 2*time.Second, 50*time.Millisecond)

	treeView, ok := receivedPayload.(types.TreeView)
	require.True(t, ok, "payload should be types.TreeView")
	assert.Contains(t, treeView.TreeViewHtml, "Snyk Open Source")
	assert.Contains(t, treeView.TreeViewHtml, "main.go")
	assert.Equal(t, 1, treeView.TotalIssues)
}

func TestTreeViewEmitter_Emit_EmptyData_SendsEmptyTree(t *testing.T) {
	c := testutil.UnitTest(t)
	notif := notification.NewNotifier()

	var receivedPayload any
	notif.CreateListener(func(params any) {
		receivedPayload = params
	})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeViewEmitter(c, notif)
	require.NoError(t, err)

	emitter.Emit(nil)

	assert.Eventually(t, func() bool {
		return receivedPayload != nil
	}, 2*time.Second, 50*time.Millisecond)

	treeView, ok := receivedPayload.(types.TreeView)
	require.True(t, ok)
	assert.Contains(t, treeView.TreeViewHtml, "<!DOCTYPE html>")
	assert.Equal(t, 0, treeView.TotalIssues)
}
