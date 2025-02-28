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
	"testing"
	"time"

	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

func Test_GetFolderTrust_shouldReturnTrustedAndUntrustedFolders(t *testing.T) {
	c := testutil.UnitTest(t)
	const trustedDummy = types.FilePath("trustedDummy")
	const untrustedDummy = types.FilePath("untrustedDummy")
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	scanStateAggregator := scanstates.NewNoopStateAggregator()

	w := New(c, performance.NewInstrumentor(), sc, nil, nil, notifier, nil, scanStateAggregator)
	c.SetTrustedFolderFeatureEnabled(true)
	c.SetTrustedFolders([]types.FilePath{trustedDummy})
	w.AddFolder(NewFolder(c, trustedDummy, string(trustedDummy), sc, nil, scanNotifier, notifier, nil, scanStateAggregator))
	w.AddFolder(NewFolder(c, untrustedDummy, string(untrustedDummy), sc, nil, scanNotifier, notifier, nil, scanStateAggregator))

	trusted, untrusted := w.GetFolderTrust()

	assert.Equal(t, trustedDummy, trusted[0].Path())
	assert.Equal(t, untrustedDummy, untrusted[0].Path())
}

func Test_TrustFoldersAndScan_shouldAddFoldersToTrustedFoldersAndTriggerScan(t *testing.T) {
	c := testutil.UnitTest(t)
	const trustedDummy = "trustedDummy"
	const untrustedDummy = "untrustedDummy"
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	w := New(c, performance.NewInstrumentor(), sc, nil, nil, notifier, nil, scanStateAggregator)
	c.SetTrustedFolderFeatureEnabled(true)
	trustedFolder := NewFolder(c, trustedDummy, trustedDummy, sc, nil, scanNotifier, notifier, nil, scanStateAggregator)
	w.AddFolder(trustedFolder)
	untrustedFolder := NewFolder(c, untrustedDummy, untrustedDummy, sc, nil, scanNotifier, notifier, nil, scanStateAggregator)
	w.AddFolder(untrustedFolder)

	w.TrustFoldersAndScan(context.Background(), []types.Folder{trustedFolder})

	assert.Contains(t, c.TrustedFolders(), trustedFolder.path)
	assert.NotContains(t, c.TrustedFolders(), untrustedFolder.path)
	assert.Eventually(t, func() bool {
		return sc.Calls() == 1
	}, time.Second, time.Millisecond, "scanner should be called after trust is granted")
}

func Test_AddAndRemoveFoldersAndReturnFolderList(t *testing.T) {
	c := testutil.UnitTest(t)
	const trustedDummy = "trustedDummy"
	const untrustedDummy = "untrustedDummy"
	const toBeRemoved = "toBeRemoved"
	trustedPathAfterConversions := uri.PathFromUri(uri.PathToUri(trustedDummy))
	toBeRemovedAbsolutePathAfterConversions := uri.PathFromUri(uri.PathToUri(toBeRemoved))
	scanStateAggregator := scanstates.NewNoopStateAggregator()

	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	w := New(c, performance.NewInstrumentor(), sc, nil, scanNotifier, notification.NewNotifier(), nil, scanStateAggregator)
	toBeRemovedFolder := NewFolder(c, toBeRemovedAbsolutePathAfterConversions, toBeRemoved, sc, nil, scanNotifier, notification.NewNotifier(), nil, scanStateAggregator)
	w.AddFolder(toBeRemovedFolder)

	c.SetTrustedFolderFeatureEnabled(true)
	c.SetTrustedFolders([]types.FilePath{trustedPathAfterConversions})
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

	folderList := w.ChangeWorkspaceFolders(params)
	assert.Nil(t, w.GetFolderContaining(toBeRemoved))

	assert.Len(t, folderList, 2)
}
