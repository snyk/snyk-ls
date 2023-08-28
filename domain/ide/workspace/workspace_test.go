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

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/uri"
)

func Test_GetFolderTrust_shouldReturnTrustedAndUntrustedFolders(t *testing.T) {
	testutil.UnitTest(t)
	const trustedDummy = "trustedDummy"
	const untrustedDummy = "untrustedDummy"
	scanner := &snyk.TestScanner{}
	scanNotifier := snyk.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	w := New(performance.NewInstrumentor(), scanner, nil, nil, notifier)
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	config.CurrentConfig().SetTrustedFolders([]string{trustedDummy})
	w.AddFolder(NewFolder(trustedDummy, trustedDummy, scanner, nil, scanNotifier, notifier))
	w.AddFolder(NewFolder(untrustedDummy, untrustedDummy, scanner, nil, scanNotifier, notifier))

	trusted, untrusted := w.GetFolderTrust()

	assert.Equal(t, trustedDummy, trusted[0].path)
	assert.Equal(t, untrustedDummy, untrusted[0].path)
}

func Test_TrustFoldersAndScan_shouldAddFoldersToTrustedFoldersAndTriggerScan(t *testing.T) {
	testutil.UnitTest(t)
	const trustedDummy = "trustedDummy"
	const untrustedDummy = "untrustedDummy"
	scanner := &snyk.TestScanner{}
	scanNotifier := snyk.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	w := New(performance.NewInstrumentor(), scanner, nil, nil, notifier)
	config.CurrentConfig().SetTrustedFolderFeatureEnabled(true)
	trustedFolder := NewFolder(trustedDummy, trustedDummy, scanner, nil, scanNotifier, notifier)
	w.AddFolder(trustedFolder)
	untrustedFolder := NewFolder(untrustedDummy, untrustedDummy, scanner, nil, scanNotifier, notifier)
	w.AddFolder(untrustedFolder)

	w.TrustFoldersAndScan(context.Background(), []*Folder{trustedFolder})

	assert.Contains(t, config.CurrentConfig().TrustedFolders(), trustedFolder.path)
	assert.NotContains(t, config.CurrentConfig().TrustedFolders(), untrustedFolder.path)
	assert.Eventually(t, func() bool {
		return scanner.Calls() == 1
	}, time.Second, time.Millisecond, "scanner should be called after trust is granted")
}

func Test_AddAndRemoveFoldersAndTriggerScan(t *testing.T) {
	testutil.UnitTest(t)
	const trustedDummy = "trustedDummy"
	const untrustedDummy = "untrustedDummy"
	const toBeRemoved = "toBeRemoved"
	trustedPathAfterConversions := uri.PathFromUri(uri.PathToUri(trustedDummy))
	toBeRemovedAbsolutePathAfterConversions := uri.PathFromUri(uri.PathToUri(toBeRemoved))

	scanner := &snyk.TestScanner{}
	scanNotifier := snyk.NewMockScanNotifier()
	w := New(performance.NewInstrumentor(), scanner, nil, scanNotifier, notification.NewNotifier())
	toBeRemovedFolder := NewFolder(toBeRemovedAbsolutePathAfterConversions, toBeRemoved, scanner, nil, scanNotifier, notification.NewNotifier())
	w.AddFolder(toBeRemovedFolder)

	currentConfig := config.CurrentConfig()
	currentConfig.SetTrustedFolderFeatureEnabled(true)
	currentConfig.SetTrustedFolders([]string{trustedPathAfterConversions})
	currentConfig.SetAutomaticScanning(true)

	params := lsp.DidChangeWorkspaceFoldersParams{Event: lsp.WorkspaceFoldersChangeEvent{
		Added: []lsp.WorkspaceFolder{
			{Name: trustedDummy, Uri: uri.PathToUri(trustedDummy)},
			{Name: untrustedDummy, Uri: uri.PathToUri(untrustedDummy)},
		},
		Removed: []lsp.WorkspaceFolder{
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
	New(nil, nil, nil, nil, nil)
	assert.Equal(t, instance, Get())
}

func Test_Set(t *testing.T) {
	w := New(nil, nil, nil, nil, nil)
	Set(w)
	assert.Equal(t, w, instance)
}
