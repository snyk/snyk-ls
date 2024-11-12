/*
 * © 2024 Snyk Limited
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

type FolderStatus int

type Clearer interface {
	Clear()
}

type ScanSnapshotClearerExister interface {
	Init(folderPath []string) error
	Clear(folderPath []string, deleteOnlyExpired bool)
	Exists(folderPath, commitHash string, p product.Product) bool
}

type Workspace interface {
	Clearer
	TrustRequester
	GetScanSnapshotClearerExister() ScanSnapshotClearerExister
	RemoveFolder(folderPath string)
	DeleteFile(filePath string)
	AddFolder(f Folder)
	GetFolderContaining(path string) Folder
	Folders() (folder []Folder)
	ScanWorkspace(ctx context.Context)
	ChangeWorkspaceFolders(params DidChangeWorkspaceFoldersParams) []Folder
	GetFolderTrust() (trusted []Folder, untrusted []Folder)
	ClearIssuesByType(removedType product.FilterableIssueType)
	TrustFoldersAndScan(ctx context.Context, foldersToBeTrusted []Folder)
}

type Folder interface {
	Clearer
	ClearDiagnosticsByIssueType(removedType product.FilterableIssueType)
	IsScanned() bool
	SetStatus(status FolderStatus)
	ScanFolder(ctx context.Context)
	ScanFile(ctx context.Context, path string)
	Contains(path string) bool
	FilterAndPublishDiagnostics(p product.Product)
	Path() string
	Uri() lsp.DocumentURI
	Name() string
	Status() FolderStatus
	IsTrusted() bool
}
