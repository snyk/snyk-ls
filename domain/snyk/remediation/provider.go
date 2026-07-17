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

	"github.com/snyk/snyk-ls/internal/types"
)

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
