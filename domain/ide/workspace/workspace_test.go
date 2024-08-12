/*
 * © 2022 Snyk Limited All rights reserved.
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

package workspace

import (
	"context"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

func Test_GetFolderTrust_shouldReturnTrustedAndUntrustedFolders(t *testing.T) {
	c := testutil.UnitTest(t)
	const trustedDummy = "trustedDummy"
	const untrustedDummy = "untrustedDummy"
	scanner := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	w := New(c, performance.NewInstrumentor(), scanner, nil, nil, notifier, nil)
	c.SetTrustedFolderFeatureEnabled(true)
	c.SetTrustedFolders([]string{trustedDummy})
	w.AddFolder(NewFolder(c, trustedDummy, trustedDummy, scanner, nil, scanNotifier, notifier, nil))
	w.AddFolder(NewFolder(c, untrustedDummy, untrustedDummy, scanner, nil, scanNotifier, notifier, nil))

	trusted, untrusted := w.GetFolderTrust()

	assert.Equal(t, trustedDummy, trusted[0].path)
	assert.Equal(t, untrustedDummy, untrusted[0].path)
}

func Test_TrustFoldersAndScan_shouldAddFoldersToTrustedFoldersAndTriggerScan(t *testing.T) {
	c := testutil.UnitTest(t)
	const trustedDummy = "trustedDummy"
	const untrustedDummy = "untrustedDummy"
	scanner := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	w := New(c, performance.NewInstrumentor(), scanner, nil, nil, notifier, nil)
	c.SetTrustedFolderFeatureEnabled(true)
	trustedFolder := NewFolder(c, trustedDummy, trustedDummy, scanner, nil, scanNotifier, notifier, nil)
	w.AddFolder(trustedFolder)
	untrustedFolder := NewFolder(c, untrustedDummy, untrustedDummy, scanner, nil, scanNotifier, notifier, nil)
	w.AddFolder(untrustedFolder)

	w.TrustFoldersAndScan(context.Background(), []*Folder{trustedFolder})

	assert.Contains(t, c.TrustedFolders(), trustedFolder.path)
	assert.NotContains(t, c.TrustedFolders(), untrustedFolder.path)
	assert.Eventually(t, func() bool {
		return scanner.Calls() == 1
	}, time.Second, time.Millisecond, "scanner should be called after trust is granted")
}

func Test_AddAndRemoveFoldersAndTriggerScan(t *testing.T) {
	c := testutil.UnitTest(t)
	const trustedDummy = "trustedDummy"
	const untrustedDummy = "untrustedDummy"
	const toBeRemoved = "toBeRemoved"
	trustedPathAfterConversions := uri.PathFromUri(uri.PathToUri(trustedDummy))
	toBeRemovedAbsolutePathAfterConversions := uri.PathFromUri(uri.PathToUri(toBeRemoved))

	scanner := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	w := New(c, performance.NewInstrumentor(), scanner, nil, scanNotifier, notification.NewNotifier(), nil)
	toBeRemovedFolder := NewFolder(c, toBeRemovedAbsolutePathAfterConversions, toBeRemoved, scanner, nil, scanNotifier, notification.NewNotifier(), nil)
	w.AddFolder(toBeRemovedFolder)

	c.SetTrustedFolderFeatureEnabled(true)
	c.SetTrustedFolders([]string{trustedPathAfterConversions})
	c.SetAutomaticScanning(true)

	params := types.DidChangeWorkspaceFoldersParams{Event: types.WorkspaceFoldersChangeEvent{
		Added: []types.WorkspaceFolder{
			{Name: trustedDummy, Uri: uri.PathToUri(trustedDummy)},
			{Name: untrustedDummy, Uri: uri.PathToUri(untrustedDummy)},
		},
		Removed: []types.WorkspaceFolder{
			{Name: toBeRemoved, Uri: uri.PathToUri(toBeRemoved)},
		},
	}}

	w.ChangeWorkspaceFolders(context.Background(), params)

	assert.Nil(t, w.GetFolderContaining(toBeRemoved))

	// one call for one trusted folder
	assert.Eventually(t, func() bool {
		return scanner.Calls() == 1
	}, time.Second, time.Millisecond, "scanner should be called after trust is granted")
}

func Test_Get(t *testing.T) {
	c := testutil.UnitTest(t)
	New(c, nil, nil, nil, nil, nil, nil)
	assert.Equal(t, instance, Get())
}

func Test_Set(t *testing.T) {
	c := testutil.UnitTest(t)
	w := New(c, nil, nil, nil, nil, nil, nil)
	Set(w)
	assert.Equal(t, w, instance)
}
