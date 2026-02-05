/*
 * © 2024-2026 Snyk Limited
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

package types

import (
	"context"

	"github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/internal/product"
)

//go:generate go tool github.com/golang/mock/mockgen -destination=mock_types/workspace_mock.go -package=mock_types github.com/snyk/snyk-ls/internal/types Workspace,Folder

type FolderStatus int

type Clearer interface {
	Clear()
}

type ScanSnapshotClearerExister interface {
	Init(folderPath []FilePath) error
	Clear(folderPath []FilePath, deleteOnlyExpired bool)
	ClearFolder(folderPath FilePath)
	Exists(folderPath FilePath, commitHash string, p product.Product) bool
}

type Workspace interface {
	Clearer
	TrustRequester
	GetScanSnapshotClearerExister() ScanSnapshotClearerExister
	RemoveFolder(folderPath FilePath)
	DeleteFile(filePath FilePath)
	AddFolder(f Folder)
	GetFolderContaining(path FilePath) Folder
	Folders() (folder []Folder)
	ScanWorkspace(ctx context.Context)
	ChangeWorkspaceFolders(params DidChangeWorkspaceFoldersParams) []Folder
	GetFolderTrust() (trusted []Folder, untrusted []Folder)
	TrustFoldersAndScan(ctx context.Context, foldersToBeTrusted []Folder)
	HandleConfigChange()
}

type Folder interface {
	Clearer
	ClearDiagnosticsByIssueType(removedType product.FilterableIssueType)
	IsScanned() bool
	SetStatus(status FolderStatus)
	ScanFolder(ctx context.Context)
	ScanFile(ctx context.Context, path FilePath)
	Contains(path FilePath) bool
	FilterAndPublishDiagnostics(p product.Product)
	Path() FilePath
	Uri() lsp.DocumentURI
	Name() string
	Status() FolderStatus
	IsTrusted() bool
	ScanResultProcessor() ScanResultProcessor
	// FolderConfigReadOnly returns the FolderConfig for this folder using read-only access
	// (no storage writes, no Git enrichment). For operations that need to create or update
	// the config, use c.FolderConfig(folder.Path()) directly.
	FolderConfigReadOnly() *FolderConfig
	// IsDeltaFindingsEnabled returns whether delta findings is enabled for this folder.
	IsDeltaFindingsEnabled() bool
	// IsAutoScanEnabled returns whether automatic scanning is enabled for this folder.
	IsAutoScanEnabled() bool
	// DisplayableIssueTypes returns which issue types are enabled for this folder.
	DisplayableIssueTypes() map[product.FilterableIssueType]bool
}
