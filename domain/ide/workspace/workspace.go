/*
 * © 2022-2024 Snyk Limited
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
	"sync"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// Workspace represents the highest entity in an IDE that contains code. A workspace may contain multiple folders
type Workspace struct {
	mutex               sync.RWMutex
	folders             map[types.FilePath]types.Folder
	instrumentor        performance.Instrumentor
	scanner             scanner.Scanner
	hoverService        hover.Service
	scanNotifier        scanner.ScanNotifier
	trustMutex          sync.Mutex
	trustRequestOngoing bool // for debouncing
	notifier            noti.Notifier
	c                   *config.Config
	scanPersister       persistence.ScanSnapshotPersister
	scanStateAggregator scanstates.Aggregator
}

func (w *Workspace) Issues() snyk.IssuesByFile {
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
	c *config.Config,
	instrumentor performance.Instrumentor,
	scanner scanner.Scanner,
	hoverService hover.Service,
	scanNotifier scanner.ScanNotifier,
	notifier noti.Notifier,
	scanPersister persistence.ScanSnapshotPersister,
	scanStateAggregator scanstates.Aggregator,
) *Workspace {
	return &Workspace{
		folders:             make(map[types.FilePath]types.Folder),
		instrumentor:        instrumentor,
		scanner:             scanner,
		hoverService:        hoverService,
		scanNotifier:        scanNotifier,
		notifier:            notifier,
		c:                   c,
		scanPersister:       scanPersister,
		scanStateAggregator: scanStateAggregator,
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

func (w *Workspace) GetFolderContaining(path types.FilePath) types.Folder {
	for _, folder := range w.folders {
		if folder.Contains(path) {
			return folder
		}
	}
	return nil
}

func (w *Workspace) Folders() (folder []types.Folder) {
	w.mutex.RLock()
	defer w.mutex.RUnlock()
	folders := make([]types.Folder, 0, len(w.folders))
	for _, folder := range w.folders {
		folders = append(folders, folder)
	}

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
		w.RemoveFolder(uri.PathFromUri(folder.Uri))
	}
	var changedWorkspaceFolders []types.Folder
	for _, folder := range params.Event.Added {
		f := NewFolder(w.c, uri.PathFromUri(folder.Uri), folder.Name, w.scanner, w.hoverService, w.scanNotifier, w.notifier, w.scanPersister, w.scanStateAggregator)
		w.AddFolder(f)
		changedWorkspaceFolders = append(changedWorkspaceFolders, f)
	}
	return changedWorkspaceFolders
}

func (w *Workspace) Clear() {
	for _, folder := range w.folders {
		if cacheProvider, ok := folder.(snyk.CacheProvider); ok {
			cacheProvider.Clear()
		}
	}

	// this should already be done for each path by the folder.Clear() and is just a fail-safe
	w.hoverService.ClearAllHovers()
}

func (w *Workspace) TrustFoldersAndScan(ctx context.Context, foldersToBeTrusted []types.Folder) {
	currentConfig := config.CurrentConfig()
	trustedFolderPaths := currentConfig.TrustedFolders()
	for _, f := range foldersToBeTrusted {
		// we need to append and set the trusted path to the config before the scan, as the scan is checking for trust
		trustedFolderPaths = append(trustedFolderPaths, f.Path())
		currentConfig.SetTrustedFolders(trustedFolderPaths)
		go f.ScanFolder(ctx)
	}
	w.notifier.Send(types.SnykTrustedFoldersParams{TrustedFolders: trustedFolderPaths})
}

func (w *Workspace) GetFolderTrust() (trusted []types.Folder, untrusted []types.Folder) {
	for _, folder := range w.folders {
		if folder.IsTrusted() {
			trusted = append(trusted, folder)
			w.c.Logger().Info().Str("folder", string(folder.Path())).Msg("Trusted folder")
		} else {
			untrusted = append(untrusted, folder)
			w.c.Logger().Info().Str("folder", string(folder.Path())).Msg("Untrusted folder")
		}
	}
	return trusted, untrusted
}

func (w *Workspace) ClearIssuesByType(removedType product.FilterableIssueType) {
	for _, folder := range w.folders {
		folder.ClearDiagnosticsByIssueType(removedType)
	}
}
