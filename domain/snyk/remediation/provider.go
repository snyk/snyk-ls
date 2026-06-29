/*
 * © 2026 Snyk Limited
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

// Package remediation defines the interface for autonomous finding remediation.
package remediation

import (
	"context"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

// RemediationRequest describes the finding for which a fix is requested.
type RemediationRequest struct {
	FindingId   string
	FilePath    types.FilePath
	ContentRoot types.FilePath
	Range       types.Range
	Product     product.Product
}

// RemediationProvider computes an autonomous fix for a single finding.
// Returns nil when no fix can be computed; callers treat nil as "no fix available".
//
// Isolation contract: implementations may mutate ContentRoot in place.
// Callers must supply an isolated copy of the workspace (e.g. a git worktree)
// as ContentRoot and are responsible for post-fix verification and rollback.
type RemediationProvider interface {
	Remediate(ctx context.Context, req RemediationRequest) (*types.WorkspaceEdit, error)
}

// FileChangeNotifier is implemented by providers that cache per-file results.
// Call InvalidateFile whenever a file is modified so that stale cached diffs
// are evicted before the user resolves another code action against that file.
type FileChangeNotifier interface {
	InvalidateFile(path types.FilePath)
}

// FolderRemediator runs the remediation fix workflow in place against an entire
// folder that is ALREADY an isolated git worktree (e.g. a detached-HEAD clone the
// caller created). It does NOT create a nested worktree. It returns a WorkspaceEdit
// whose file paths are keyed under root (root/<relpath>); the caller delivers
// those edits to the client (e.g. via workspace/applyEdit). Returns (nil, nil) when
// the fix produces no changes.
//
// Precondition: root must be an absolute path to the git repository root (top
// level). Passing a subdirectory of a git repo is rejected with a clear error so
// the fix runner cannot silently escape its isolation boundary. The daemon caller
// always passes a detached-HEAD worktree root, and edits are keyed under that
// root so the caller can remap paths using the passed-folder prefix.
type FolderRemediator interface {
	FixFolder(ctx context.Context, root types.FilePath) (*types.WorkspaceEdit, error)
}
