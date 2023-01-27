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
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/uri"
)

// todo can we do without a singleton?
var instance *Workspace
var mutex = &sync.Mutex{}

// Workspace represents the highest entity in an IDE that contains code. A workspace may contain multiple folders
type Workspace struct {
	mutex               sync.Mutex
	folders             map[string]*Folder
	instrumentor        performance.Instrumentor
	scanner             snyk.Scanner
	hoverService        hover.Service
	scanNotifier        snyk.ScanNotifier
	trustMutex          sync.Mutex
	trustRequestOngoing bool // for debouncing
}

func New(instrumentor performance.Instrumentor, scanner snyk.Scanner, hoverService hover.Service, scanNotifier snyk.ScanNotifier) *Workspace {
	return &Workspace{
		folders:      make(map[string]*Folder, 0),
		instrumentor: instrumentor,
		scanner:      scanner,
		hoverService: hoverService,
		scanNotifier: scanNotifier,
	}
}

// todo can we move to di?
func Get() *Workspace {
	mutex.Lock()
	defer mutex.Unlock()
	return instance
}

func Set(w *Workspace) {
	mutex.Lock()
	defer mutex.Unlock()
	instance = w
}

func (w *Workspace) RemoveFolder(folderPath string) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	folder := w.GetFolderContaining(folderPath)
	if folder == nil {
		return
	}
	folder.ClearDiagnosticsFromPathRecursively(folderPath)
	delete(w.folders, folderPath)
}

func (w *Workspace) DeleteFile(filePath string) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	folder := w.GetFolderContaining(filePath)
	if folder != nil {
		folder.ClearDiagnosticsFromFile(filePath)
	}
}

func (w *Workspace) AddFolder(f *Folder) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	if w.folders == nil {
		w.folders = map[string]*Folder{}
	}
	w.folders[f.Path()] = f
}

func (w *Workspace) GetFolderContaining(path string) (folder *Folder) {
	for _, folder := range w.folders {
		if folder.Contains(path) {
			return folder
		}
	}
	return nil
}

func (w *Workspace) Folders() (folder []*Folder) {
	folders := make([]*Folder, 0, len(w.folders))
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
func (w *Workspace) ChangeWorkspaceFolders(ctx context.Context, params lsp.DidChangeWorkspaceFoldersParams) {
	for _, folder := range params.Event.Removed {
		w.RemoveFolder(uri.PathFromUri(folder.Uri))
	}
	for _, folder := range params.Event.Added {
		f := NewFolder(uri.PathFromUri(folder.Uri), folder.Name, w.scanner, w.hoverService, w.scanNotifier)
		w.AddFolder(f)
	}

	if config.CurrentConfig().IsAutoScanEnabled() {
		w.ScanWorkspace(ctx)
	}
}

func (w *Workspace) ClearIssues(_ context.Context) {
	for _, folder := range w.folders {
		folder.ClearScannedStatus()
		folder.ClearDiagnostics()
	}

	w.hoverService.ClearAllHovers()
}

func (w *Workspace) TrustFoldersAndScan(ctx context.Context, foldersToBeTrusted []*Folder) {
	currentConfig := config.CurrentConfig()
	trustedFolderPaths := currentConfig.TrustedFolders()
	for _, f := range foldersToBeTrusted {
		// we need to append and set the trusted path to the config before the scan, as the scan is checking for trust
		trustedFolderPaths = append(trustedFolderPaths, f.Path())
		currentConfig.SetTrustedFolders(trustedFolderPaths)
		go f.ScanFolder(ctx)
	}
	notification.Send(lsp.SnykTrustedFoldersParams{TrustedFolders: trustedFolderPaths})
}

func (w *Workspace) GetFolderTrust() (trusted []*Folder, untrusted []*Folder) {
	for _, folder := range w.folders {
		if folder.IsTrusted() {
			trusted = append(trusted, folder)
			log.Info().Str("folder", folder.Path()).Msg("Trusted folder")
		} else {
			untrusted = append(untrusted, folder)
			log.Info().Str("folder", folder.Path()).Msg("Untrusted folder")
		}
	}
	return trusted, untrusted
}

func (w *Workspace) ClearIssuesByType(removedType product.FilterableIssueType) {
	for _, folder := range w.folders {
		folder.ClearDiagnosticsByIssueType(removedType)
	}
}
