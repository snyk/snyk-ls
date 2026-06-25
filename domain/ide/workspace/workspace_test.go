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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"

	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

// TestGetFolderTrust_ConcurrentAddFolder_NoDataRace guards against the data race
// between GetFolderTrust (which reads w.folders) and AddFolder (which writes
// w.folders under w.mutex). The PR added GetFolderTrust to the tree-render path
// (tree_builder.go), making it reachable concurrently with folder mutations.
// w.mutex.RLock must be held across the w.folders iteration in GetFolderTrust.
// (IDE-1882)
//
// The loop runs 200 iterations to give the race detector enough scheduling
// opportunities to reliably surface the bug when the lock is absent. A single
// goroutine pair is a weak signal; 200 pairs make a missed race effectively
// impossible in practice.
//
// Run with -race to catch the concurrent read/write:
//
//	go test -race ./domain/ide/workspace/... -run TestGetFolderTrust_ConcurrentAddFolder_NoDataRace
func TestGetFolderTrust_ConcurrentAddFolder_NoDataRace(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	resolver := defaultResolver(engine)

	w := New(conf, logger, performance.NewInstrumentor(), sc, nil, scanNotifier, notification.NewNotifier(), nil, scanStateAggregator, featureflag.NewFakeService(), resolver, engine)

	// Pre-populate so GetFolderTrust has something to iterate over.
	existing := NewFolder(conf, logger, types.PathKey("existing-folder"), "existing-folder", sc, nil, scanNotifier, notification.NewNotifier(), nil, scanStateAggregator, featureflag.NewFakeService(), resolver, engine)
	w.AddFolder(existing)

	for i := 0; i < 200; i++ {
		// Use a unique key per iteration so that AddFolder always performs a
		// genuine map write (not a no-op on an already-present key). The
		// AddFolder guard `if w.folders[f.Path()] == nil` would skip the write
		// on iterations 2-200 if we reused the same key, leaving the race
		// window open for only the first iteration.
		name := fmt.Sprintf("dynamic-folder-%d", i)
		folderKey := types.PathKey(types.FilePath(name))
		newF := NewFolder(conf, logger, folderKey, name, sc, nil, scanNotifier, notification.NewNotifier(), nil, scanStateAggregator, featureflag.NewFakeService(), resolver, engine)

		// Race: GetFolderTrust reads w.folders while AddFolder writes it.
		// Without w.mutex.RLock in GetFolderTrust the race detector reports a
		// data race here.
		var start sync.WaitGroup
		start.Add(1)
		var done sync.WaitGroup
		done.Add(2)

		go func() {
			defer done.Done()
			start.Wait()
			w.GetFolderTrust()
		}()
		go func() {
			defer done.Done()
			start.Wait()
			w.AddFolder(newF)
		}()
		start.Done()
		done.Wait()
	}
}

// Test_Folders_ReturnsSortedOrder verifies that Workspace.Folders() always returns a deterministically
// ordered slice sorted by folder.Path() ascending, regardless of Go map iteration order.
//
// Root cause (IDE-2149 follow-up): Workspace.Folders() ranges over a map, so the returned slice
// order is randomized per call. Any consumer that compares two consecutive results — notably the
// reflect.DeepEqual guard that suppresses the $/snyk.configuration infinite refresh loop — can see
// a spurious difference and misfire. Fixing at the source makes every Folders() consumer deterministic.
//
// This test adds 8 folders in intentionally non-sorted path order and asserts:
//  1. The returned slice is sorted by Path() ascending on every call.
//  2. Fifty consecutive calls all produce a reflect.DeepEqual result.
func Test_Folders_ReturnsSortedOrder(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	notifier := notification.NewNotifier()
	scanStateAggregator := scanstates.NewNoopStateAggregator()

	w := New(conf, logger, performance.NewInstrumentor(), sc, nil, scanNotifier, notifier, nil, scanStateAggregator, featureflag.NewFakeService(), defaultResolver(engine), engine)

	// Insert paths in intentionally non-sorted order so randomized map iteration is likely to
	// expose a different ordering on repeated calls if the source is not sorted.
	paths := []types.FilePath{
		"/workspace/h",
		"/workspace/a",
		"/workspace/f",
		"/workspace/b",
		"/workspace/g",
		"/workspace/c",
		"/workspace/e",
		"/workspace/d",
	}
	for _, p := range paths {
		w.AddFolder(NewFolder(conf, logger, p, string(p), sc, nil, scanNotifier, notifier, nil, scanStateAggregator, featureflag.NewFakeService(), defaultResolver(engine), engine))
	}

	first := w.Folders()
	require.Len(t, first, len(paths), "all folders must be returned")

	// Assert sorted ascending order.
	for i := 1; i < len(first); i++ {
		assert.LessOrEqual(t, string(first[i-1].Path()), string(first[i].Path()),
			"Folders()[%d].Path() (%q) must be <= Folders()[%d].Path() (%q)",
			i-1, first[i-1].Path(), i, first[i].Path())
	}

	// 50 consecutive calls must all be reflect.DeepEqual to the first call.
	for iter := 0; iter < 50; iter++ {
		got := w.Folders()
		require.Equal(t, first, got,
			"iteration %d: Folders() result must be identical to the first call (path order mismatch)",
			iter)
	}
}
