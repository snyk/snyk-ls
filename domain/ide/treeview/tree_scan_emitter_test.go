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

	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestTreeScanStateEmitter_Emit_SendsTreeViewNotification(t *testing.T) {
	c := testutil.UnitTest(t)
	notif := notification.NewNotifier()

	var receivedPayload any
	notif.CreateListener(func(params any) {
		receivedPayload = params
	})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeScanStateEmitter(c, notif)
	require.NoError(t, err)

	// Emit with a snapshot that indicates a scan is in progress
	emitter.Emit(scanstates.StateSnapshot{
		AnyScanInProgressWorkingDirectory: true,
	})

	assert.Eventually(t, func() bool {
		return receivedPayload != nil
	}, 2*time.Second, 50*time.Millisecond)

	treeView, ok := receivedPayload.(types.TreeView)
	require.True(t, ok, "payload should be types.TreeView")
	assert.Contains(t, treeView.TreeViewHtml, "<!DOCTYPE html>")
}

func TestTreeScanStateEmitter_Emit_ScanInProgress_HasScanningIndicator(t *testing.T) {
	c := testutil.UnitTest(t)
	notif := notification.NewNotifier()

	var receivedPayload any
	notif.CreateListener(func(params any) {
		receivedPayload = params
	})
	t.Cleanup(func() { notif.DisposeListener() })

	emitter, err := NewTreeScanStateEmitter(c, notif)
	require.NoError(t, err)

	emitter.Emit(scanstates.StateSnapshot{
		AnyScanInProgressWorkingDirectory: true,
	})

	assert.Eventually(t, func() bool {
		return receivedPayload != nil
	}, 2*time.Second, 50*time.Millisecond)

	treeView := receivedPayload.(types.TreeView)
	assert.Contains(t, treeView.TreeViewHtml, "scanning")
}
