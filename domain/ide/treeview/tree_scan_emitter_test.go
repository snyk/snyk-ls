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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestTreeScanStateEmitter_Emit_SendsTreeViewNotification(t *testing.T) {
	c := testutil.UnitTest(t)
	notif := notification.NewNotifier()

	var mu sync.Mutex
	var receivedPayload any
	notif.CreateListener(func(params any) {
		mu.Lock()
		defer mu.Unlock()
		receivedPayload = params
	})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeScanStateEmitter(c, notif)
	require.NoError(t, err)
	t.Cleanup(emitter.Dispose)

	emitter.Emit(scanstates.StateSnapshot{
		AnyScanInProgressWorkingDirectory: true,
	})

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return receivedPayload != nil
	}, 2*time.Second, 50*time.Millisecond)

	mu.Lock()
	treeView, ok := receivedPayload.(types.TreeView)
	mu.Unlock()
	require.True(t, ok, "payload should be types.TreeView")
	assert.Contains(t, treeView.TreeViewHtml, "<!DOCTYPE html>")
}

func TestTreeScanStateEmitter_Emit_ScanInProgress_HasScanningInProductNode(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykCodeEnabled(true)
	c.SetSnykOssEnabled(true)
	c.SetSnykIacEnabled(true)

	// Set up workspace so product nodes are rendered.
	workspaceutil.SetupWorkspace(t, c, "/project")

	notif := notification.NewNotifier()

	var mu sync.Mutex
	var receivedPayload any
	notif.CreateListener(func(params any) {
		mu.Lock()
		defer mu.Unlock()
		receivedPayload = params
	})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeScanStateEmitter(c, notif)
	require.NoError(t, err)
	t.Cleanup(emitter.Dispose)

	folderKey := types.PathKey("/project")
	emitter.Emit(scanstates.StateSnapshot{
		AnyScanInProgressWorkingDirectory: true,
		ProductScanStates: map[types.FilePath]map[product.Product]bool{
			folderKey: {product.ProductCode: true},
		},
	})

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return receivedPayload != nil
	}, 2*time.Second, 50*time.Millisecond)

	mu.Lock()
	treeView := receivedPayload.(types.TreeView)
	mu.Unlock()
	assert.Contains(t, treeView.TreeViewHtml, "Scanning...", "scanning indicator should be in product node description, not global banner")
	assert.NotContains(t, treeView.TreeViewHtml, `id="scanStatus"`, "global scanning banner element should be removed")
}

func TestTreeScanStateEmitter_Emit_ConcurrentCallsNoRace(t *testing.T) {
	c := testutil.UnitTest(t)
	workspaceutil.SetupWorkspace(t, c, "/project")

	notif := notification.NewNotifier()
	notif.CreateListener(func(params any) {})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeScanStateEmitter(c, notif)
	require.NoError(t, err)
	t.Cleanup(emitter.Dispose)

	folderKey := types.PathKey("/project")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			emitter.Emit(scanstates.StateSnapshot{
				ProductScanStates: map[types.FilePath]map[product.Product]bool{
					folderKey: {product.ProductCode: true},
				},
			})
		}()
	}
	wg.Wait()
}

func TestTreeScanStateEmitter_Emit_PerProductScanStatus(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetSnykCodeEnabled(true)
	c.SetSnykOssEnabled(true)
	c.SetSnykIacEnabled(true)

	// Set up a workspace with a folder so that product nodes are generated.
	workspaceutil.SetupWorkspace(t, c, "/project")

	notif := notification.NewNotifier()

	var mu sync.Mutex
	var receivedPayload any
	notif.CreateListener(func(params any) {
		mu.Lock()
		defer mu.Unlock()
		receivedPayload = params
	})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeScanStateEmitter(c, notif)
	require.NoError(t, err)
	t.Cleanup(emitter.Dispose)

	folderKey := types.PathKey("/project")
	emitter.Emit(scanstates.StateSnapshot{
		AnyScanInProgressWorkingDirectory: true,
		ProductScanStates: map[types.FilePath]map[product.Product]bool{
			folderKey: {
				product.ProductCode:                 true,
				product.ProductOpenSource:           false,
				product.ProductInfrastructureAsCode: false,
			},
		},
	})

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return receivedPayload != nil
	}, 2*time.Second, 50*time.Millisecond)

	mu.Lock()
	treeView := receivedPayload.(types.TreeView)
	mu.Unlock()
	assert.Contains(t, treeView.TreeViewHtml, "Scanning...", "Code product node should show Scanning... since its scan is in progress")
}

func TestTreeScanStateEmitter_Dispose_StopsRenderLoop(t *testing.T) {
	c := testutil.UnitTest(t)
	notif := notification.NewNotifier()
	notif.CreateListener(func(params any) {})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeScanStateEmitter(c, notif)
	require.NoError(t, err)

	emitter.Dispose()
	// Double-dispose must not panic.
	emitter.Dispose()

	// Emit after Dispose must not block or panic.
	emitter.Emit(scanstates.StateSnapshot{AnyScanInProgressWorkingDirectory: true})
}
