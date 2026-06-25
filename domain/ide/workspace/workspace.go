/*
 * © 2022-2026 Snyk Limited
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
	"encoding/json"
	"sort"
	"sync"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/analytics"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// Workspace represents the highest entity in an IDE that contains code. A workspace may contain multiple folders.
//
// Mutex ordering (must always be acquired in this order to prevent deadlocks):
//
//  1. mutex — protects w.folders; acquired via Lock() for writes and RLock()
//     for reads. Never acquire trustStateMutex while holding mutex.
//  2. trustStateMutex — protects trust-specific state (see below). Always
//     acquired AFTER mutex is released, never while mutex is held.
type Workspace struct {
	mutex        sync.RWMutex
	folders      map[types.FilePath]types.Folder
	instrumentor performance.Instrumentor
	scanner      scanner.Scanner
	hoverService hover.Service
	scanNotifier scanner.ScanNotifier
	// trustStateMutex guards two trust-related invariants:
	//   1. trustRequestOngoing — debounce flag for the UI trust dialog
	//   2. the addTrustedFolders read-modify-write on SettingTrustedFolders
	// Both are serialized by the same lock so there is a single mutex ordering
	// between all trust state mutations. (IDE-1882)
	trustStateMutex     sync.Mutex
	trustRequestOngoing bool // for debouncing
	notifier            noti.Notifier
	conf                configuration.Configuration
	logger              *zerolog.Logger
	scanPersister       persistence.ScanSnapshotPersister
	scanStateAggregator scanstates.Aggregator
	featureFlagService  featureflag.Service
	configResolver      types.ConfigResolverInterface
	engine              workflow.Engine
}

func (w *Workspace) Issues() snyk.IssuesByFile {
	// Hold the read lock while iterating w.folders to prevent a data race with
	// concurrent AddFolder / RemoveFolder (which write the map under Lock()).
	w.mutex.RLock()
	defer w.mutex.RUnlock()
	issues := make(map[types.FilePath][]types.Issue)
	for _, folder := range w.folders {
		if issueProvider, ok := folder.(snyk.IssueProvider); ok {
			for filePath, issueSlice := range issueProvider.Issues() {
				issues[filePath] = append(issues[filePath], issueSlice...)
			}
		}
	}
	return issues
}

func (w *Workspace) Issue(key string) types.Issue {
	// Hold the read lock while iterating w.folders to prevent a data race with
	// concurrent AddFolder / RemoveFolder (which write the map under Lock()).
	w.mutex.RLock()
	defer w.mutex.RUnlock()
	for _, folder := range w.folders {
		if issueProvider, ok := folder.(snyk.IssueProvider); ok {
			issue := issueProvider.Issue(key)
			if issue != nil && issue.GetID() != "" {
				return issue
			}
		}
	}
	return nil
}

func New(
	conf configuration.Configuration,
	logger *zerolog.Logger,
	instrumentor performance.Instrumentor,
	scanner scanner.Scanner,
	hoverService hover.Service,
	scanNotifier scanner.ScanNotifier,
	notifier noti.Notifier,
	scanPersister persistence.ScanSnapshotPersister,
	scanStateAggregator scanstates.Aggregator,
	featureFlagService featureflag.Service,
	configResolver types.ConfigResolverInterface,
	engine workflow.Engine,
) *Workspace {
	return &Workspace{
		folders:             make(map[types.FilePath]types.Folder),
		instrumentor:        instrumentor,
		scanner:             scanner,
		hoverService:        hoverService,
		scanNotifier:        scanNotifier,
		notifier:            notifier,
		conf:                conf,
		logger:              logger,
		scanPersister:       scanPersister,
		scanStateAggregator: scanStateAggregator,
		featureFlagService:  featureFlagService,
		configResolver:      configResolver,
		engine:              engine,
	}
}

func (w *Workspace) HandleConfigChange() {
	for _, folder := range w.Folders() {
		sendPublishDiagnosticsForAllProducts(folder)
	}
	w.scanStateAggregator.SummaryEmitter().Emit(w.scanStateAggregator.StateSnapshot())
}

func sendPublishDiagnosticsForAllProducts(folder types.Folder) {
	folder.FilterAndPublishDiagnostics(product.ProductOpenSource)
	folder.FilterAndPublishDiagnostics(product.ProductInfrastructureAsCode)
	folder.FilterAndPublishDiagnostics(product.ProductCode)
	folder.FilterAndPublishDiagnostics(product.ProductSecrets)
}

func (w *Workspace) GetScanSnapshotClearerExister() types.ScanSnapshotClearerExister {
	return w.scanPersister
}

func (w *Workspace) RemoveFolder(folderPath types.FilePath) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	folder := w.GetFolderContaining(folderPath)
	if folder == nil {
		return
	}
	if cacheProvider, ok := folder.(snyk.CacheProvider); ok {
		cacheProvider.Clear()
	}
	delete(w.folders, folderPath)
}

func (w *Workspace) DeleteFile(filePath types.FilePath) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	folder := w.GetFolderContaining(filePath)
	if cacheProvider, ok := folder.(snyk.CacheProvider); ok {
		if folder != nil {
			cacheProvider.ClearIssues(filePath)
		}
	}
}

func (w *Workspace) AddFolder(f types.Folder) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	if w.folders == nil {
		w.folders = map[types.FilePath]types.Folder{}
	}
	if w.folders[f.Path()] == nil {
		w.folders[f.Path()] = f
	}
}

func (w *Workspace) IssuesForFile(path types.FilePath) []types.Issue {
	folder := w.GetFolderContaining(path)
	if folder == nil {
		return nil
	}

	if issueProvider, ok := folder.(snyk.IssueProvider); ok {
		return issueProvider.IssuesForFile(path)
	}

	return nil
}

func (w *Workspace) IssuesForRange(path types.FilePath, r types.Range) []types.Issue {
	folder := w.GetFolderContaining(path)
	if folder == nil {
		return nil
	}

	if issueProvider, ok := folder.(snyk.IssueProvider); ok {
		return issueProvider.IssuesForRange(path, r)
	}

	return nil
}

// GetFolderContaining returns the first folder that contains the given path, or
// nil if none does.
//
// CONCURRENCY: callers must NOT hold w.mutex when calling this function — it reads
// w.folders bare (no lock). RemoveFolder and DeleteFile already call it while
// holding w.mutex.Lock(); adding a lock here would deadlock those callers.
// A follow-up is needed to audit and protect all w.folders iterators uniformly.
func (w *Workspace) GetFolderContaining(path types.FilePath) types.Folder {
	for _, folder := range w.folders {
		if folder.Contains(path) {
			return folder
		}
	}
	return nil
}

func (w *Workspace) Folders() []types.Folder {
	folders := func() []types.Folder {
		w.mutex.RLock()
		defer w.mutex.RUnlock()
		result := make([]types.Folder, 0, len(w.folders))
		for _, folder := range w.folders {
			result = append(result, folder)
		}
		return result
	}()
	sort.Slice(folders, func(i, j int) bool {
		return folders[i].Path() < folders[j].Path()
	})
	return folders
}

func (w *Workspace) ScanWorkspace(ctx context.Context) {
	trusted, _ := w.GetFolderTrust()

	for _, folder := range trusted {
		go folder.ScanFolder(ctx)
	}
}

// ChangeWorkspaceFolders clears the "Removed" folders, adds the "New" folders,
// and starts an automatic scan if auto-scans are enabled.
func (w *Workspace) ChangeWorkspaceFolders(params types.DidChangeWorkspaceFoldersParams) []types.Folder {
	for _, folder := range params.Event.Removed {
		pathFromUri := types.PathKey(uri.PathFromUri(folder.Uri))
		w.RemoveFolder(pathFromUri)
	}
	var changedWorkspaceFolders []types.Folder
	for _, folder := range params.Event.Added {
		pathFromUri := types.PathKey(uri.PathFromUri(folder.Uri))
		f := NewFolder(w.conf, w.logger, pathFromUri, folder.Name, w.scanner, w.hoverService, w.scanNotifier, w.notifier, w.scanPersister, w.scanStateAggregator, w.featureFlagService, w.configResolver, w.engine)
		w.AddFolder(f)
		changedWorkspaceFolders = append(changedWorkspaceFolders, f)
	}
	return changedWorkspaceFolders
}

func (w *Workspace) Clear() {
	// Snapshot the folder list under the read lock so that concurrent
	// AddFolder / RemoveFolder calls do not race with the map iteration.
	// The lock is released before calling per-folder Clear() for two reasons:
	//   1. Avoid holding w.mutex during potentially slow I/O in folder.Clear().
	//   2. Folder.Clear() is concurrency-safe by its own internal mutex and
	//      xsync.MapOf fields — concurrent invocations (e.g. from a concurrent
	//      RemoveFolder) are safe and idempotent.
	// A folder added after the snapshot is taken will not be cleared by this
	// call; that is intentional point-in-time semantics.
	w.mutex.RLock()
	folders := make([]types.Folder, 0, len(w.folders))
	for _, folder := range w.folders {
		folders = append(folders, folder)
	}
	w.mutex.RUnlock()

	for _, folder := range folders {
		if cacheProvider, ok := folder.(snyk.CacheProvider); ok {
			cacheProvider.Clear()
		}
	}

	// this should already be done for each path by the folder.Clear() and is just a fail-safe
	w.hoverService.ClearAllHovers()
}

// addTrustedFolders appends foldersToSet to the SettingTrustedFolders config
// key and returns the resulting full slice so callers do not need to re-read
// config to build notification payloads.
//
// CONCURRENCY: callers that may run concurrently must hold Workspace.trustStateMutex
// for the duration of this call. The function is package-level (no receiver) and
// cannot acquire the lock itself.
func addTrustedFolders(conf configuration.Configuration, configResolver types.ConfigResolverInterface, logger *zerolog.Logger, engine workflow.Engine, foldersToSet []types.Folder) []types.FilePath {
	oldTrustedFolderPaths := types.GetGlobalSliceFilePath(conf, types.SettingTrustedFolders)

	trustedFolderPaths := append([]types.FilePath(nil), oldTrustedFolderPaths...)
	for _, folder := range foldersToSet {
		logger.Debug().Str("method", "addTrustedFolders").Msgf("adding trusted folder %s", folder.Path())
		trustedFolderPaths = append(trustedFolderPaths, folder.Path())
	}

	types.SetGlobalUser(conf, types.SettingTrustedFolders, trustedFolderPaths)

	if conf.GetBool(types.SettingIsLspInitialized) {
		oldFoldersJSON, _ := json.Marshal(oldTrustedFolderPaths)
		newFoldersJSON, _ := json.Marshal(trustedFolderPaths)
		go analytics.SendConfigChangedAnalyticsEvent(conf, engine, logger, "trustedFolders", string(oldFoldersJSON), string(newFoldersJSON), types.FilePath(""), analytics.TriggerSourceIDE, configResolver)
	}
	return trustedFolderPaths
}

func (w *Workspace) TrustFoldersAndScan(ctx context.Context, foldersToBeTrusted []types.Folder) {
	// Guard the read-modify-write in addTrustedFolders: two concurrent calls
	// (e.g. user clicking "Trust" on two banner buttons simultaneously) would
	// both read the same old trusted-folder list, append their folder, and the
	// last writer would drop the other's folder. trustStateMutex serializes the
	// Get+Set pair so neither call loses its update. (IDE-1882)
	//
	// addTrustedFolders returns the full post-write slice so we avoid a
	// second config read (which could observe a different writer's update).
	// The closure scopes the defer-unlock so the mutex is released before
	// notifier.Send and the goroutine launches below.
	trustedFolderPaths := func() []types.FilePath {
		w.trustStateMutex.Lock()
		defer w.trustStateMutex.Unlock()
		return addTrustedFolders(w.conf, w.configResolver, w.logger, w.engine, foldersToBeTrusted)
	}()
	w.notifier.Send(types.SnykTrustedFoldersParams{TrustedFolders: trustedFolderPaths})
	for _, f := range foldersToBeTrusted {
		go f.ScanFolder(ctx)
	}
}

func (w *Workspace) GetFolderTrust() (trusted []types.Folder, untrusted []types.Folder) {
	// Hold the read lock while iterating w.folders to prevent a data race with
	// concurrent AddFolder / RemoveFolder calls. GetFolderTrust is called from
	// the tree-render path (tree_builder.go) which runs concurrently with folder
	// mutations. Mirror the pattern used by Folders(). (IDE-1882)
	w.mutex.RLock()
	defer w.mutex.RUnlock()
	for _, folder := range w.folders {
		if folder.IsTrusted() {
			trusted = append(trusted, folder)
			w.logger.Debug().Str("folder", string(folder.Path())).Msg("Trusted folder")
		} else {
			untrusted = append(untrusted, folder)
			w.logger.Debug().Str("folder", string(folder.Path())).Msg("Untrusted folder")
		}
	}
	return trusted, untrusted
}
