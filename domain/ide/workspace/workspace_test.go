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
	"sync"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"

	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

func Test_GetFolderTrust_shouldReturnTrustedAndUntrustedFolders(t *testing.T) {
	engine := testutil.UnitTest(t)
	const trustedDummy = types.FilePath("trustedDummy")
	const untrustedDummy = types.FilePath("untrustedDummy")
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	scanStateAggregator := scanstates.NewNoopStateAggregator()

	conf := engine.GetConfiguration()
	logger := engine.GetLogger()
	w := New(conf, logger, performance.NewInstrumentor(), sc, nil, nil, notifier, nil, scanStateAggregator, featureflag.NewFakeService(), defaultResolver(engine), engine)
	conf.Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingTrustedFolders), []types.FilePath{trustedDummy})
	w.AddFolder(NewFolder(conf, logger, trustedDummy, string(trustedDummy), sc, nil, scanNotifier, notifier, nil, scanStateAggregator, featureflag.NewFakeService(), defaultResolver(engine), engine))
	w.AddFolder(NewFolder(conf, logger, untrustedDummy, string(untrustedDummy), sc, nil, scanNotifier, notifier, nil, scanStateAggregator, featureflag.NewFakeService(), defaultResolver(engine), engine))

	trusted, untrusted := w.GetFolderTrust()

	assert.Equal(t, trustedDummy, trusted[0].Path())
	assert.Equal(t, untrustedDummy, untrusted[0].Path())
}

func Test_TrustFoldersAndScan_shouldAddFoldersToTrustedFoldersAndTriggerScan(t *testing.T) {
	engine := testutil.UnitTest(t)
	const trustedDummy = "trustedDummy"
	const untrustedDummy = "untrustedDummy"
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()
	w := New(conf, logger, performance.NewInstrumentor(), sc, nil, nil, notifier, nil, scanStateAggregator, featureflag.NewFakeService(), defaultResolver(engine), engine)
	conf.Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)
	trustedFolder := NewFolder(conf, logger, types.PathKey(trustedDummy), trustedDummy, sc, nil, scanNotifier, notifier, nil, scanStateAggregator, featureflag.NewFakeService(), defaultResolver(engine), engine)
	w.AddFolder(trustedFolder)
	untrustedFolder := NewFolder(conf, logger, types.PathKey(untrustedDummy), untrustedDummy, sc, nil, scanNotifier, notifier, nil, scanStateAggregator, featureflag.NewFakeService(), defaultResolver(engine), engine)
	w.AddFolder(untrustedFolder)

	w.TrustFoldersAndScan(t.Context(), []types.Folder{trustedFolder})

	trustedFolders := types.GetGlobalSliceFilePath(engine.GetConfiguration(), types.SettingTrustedFolders)
	assert.Contains(t, trustedFolders, trustedFolder.path)
	assert.NotContains(t, trustedFolders, untrustedFolder.path)
	assert.Eventually(t, func() bool {
		return sc.Calls() == 1
	}, time.Second, time.Millisecond, "scanner should be called after trust is granted")
}

// TestTrustFoldersAndScan_ConcurrentCalls_BothFoldersTrusted guards against the
// read-modify-write race in addTrustedFolders: two concurrent TrustFoldersAndScan
// calls both read the old trusted-folder list, append their own folder, then write
// back — the last writer wins and drops the other folder. trustStateMutex must guard
// the read-modify-write to prevent this. (IDE-1882)
//
// NOTE: run with -race (go test -race) to detect the concurrent read-modify-write
// as a memory-safety violation in addition to the functional assertion below.
func TestTrustFoldersAndScan_ConcurrentCalls_BothFoldersTrusted(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	resolver := defaultResolver(engine)

	conf.Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)

	w := New(conf, logger, performance.NewInstrumentor(), sc, nil, scanNotifier, notification.NewNotifier(), nil, scanStateAggregator, featureflag.NewFakeService(), resolver, engine)

	f1 := NewFolder(conf, logger, types.PathKey("folder-one"), "folder-one", sc, nil, scanNotifier, notification.NewNotifier(), nil, scanStateAggregator, featureflag.NewFakeService(), resolver, engine)
	f2 := NewFolder(conf, logger, types.PathKey("folder-two"), "folder-two", sc, nil, scanNotifier, notification.NewNotifier(), nil, scanStateAggregator, featureflag.NewFakeService(), resolver, engine)
	w.AddFolder(f1)
	w.AddFolder(f2)

	// Fire both trust operations concurrently from a standing start so the
	// read-modify-write window is maximally exposed. Without trustStateMutex
	// guarding addTrustedFolders, the race detector would report a data race
	// here and one folder would be silently dropped.
	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	done.Add(2)
	go func() {
		defer done.Done()
		start.Wait()
		w.TrustFoldersAndScan(t.Context(), []types.Folder{f1})
	}()
	go func() {
		defer done.Done()
		start.Wait()
		w.TrustFoldersAndScan(t.Context(), []types.Folder{f2})
	}()
	start.Done() // release both goroutines simultaneously
	done.Wait()

	trusted := types.GetGlobalSliceFilePath(conf, types.SettingTrustedFolders)
	assert.Contains(t, trusted, f1.Path(), "folder-one must be trusted after concurrent calls")
	assert.Contains(t, trusted, f2.Path(), "folder-two must be trusted after concurrent calls")
}

func Test_AddAndRemoveFoldersAndReturnFolderList(t *testing.T) {
	engine := testutil.UnitTest(t)
	const trustedDummy = "trustedDummy"
	const untrustedDummy = "untrustedDummy"
	const toBeRemoved = "toBeRemoved"
	trustedPathAfterConversions := uri.PathFromUri(uri.PathToUri(trustedDummy))
	toBeRemovedAbsolutePathAfterConversions := uri.PathFromUri(uri.PathToUri(toBeRemoved))
	scanStateAggregator := scanstates.NewNoopStateAggregator()

	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()
	w := New(conf, logger, performance.NewInstrumentor(), sc, nil, scanNotifier, notification.NewNotifier(), nil, scanStateAggregator, featureflag.NewFakeService(), defaultResolver(engine), engine)
	toBeRemovedFolder := NewFolder(conf, logger, toBeRemovedAbsolutePathAfterConversions, toBeRemoved, sc, nil, scanNotifier, notification.NewNotifier(), nil, scanStateAggregator, featureflag.NewFakeService(), defaultResolver(engine), engine)
	w.AddFolder(toBeRemovedFolder)

	conf.Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingTrustedFolders), []types.FilePath{trustedPathAfterConversions})
	conf.Set(configresolver.UserGlobalKey(types.SettingScanAutomatic), true)

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
