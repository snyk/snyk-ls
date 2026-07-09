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

package types

// FolderFixFileResult is one entry in a fixFolder result: a single tracked file
// the agentic fix changed or deleted.
//
// FolderFixFileResult covers modifications and deletions of TRACKED files. Because
// the underlying git enumeration uses --no-renames, a rename surfaces as a deletion
// of the old path (WorktreePath=""); the new path, being previously untracked, is
// outside the current contract. A newly-created untracked file is likewise outside
// the contract and does not appear in results.
//
// For edits (file modified): WorktreePath and WorkspacePath are identical under the
// current contract — FixFolder runs the fix directly in the workspace path that was
// passed as the run root, so both fields hold the same absolute on-disk path.
// WorktreePath is the daemon's copy source (the finished file to read from) and
// WorkspacePath is the remap target (the workspace file to overwrite). If these paths
// ever diverge (e.g. a separate worktree is introduced), WorktreePath is the source
// and WorkspacePath is the destination.
//
// For deletions (file removed by the fix): WorktreePath is empty (""). The
// daemon deletes the workspace file at WorkspacePath's mapped location instead
// of copying. Diff still contains the unified deletion diff from HEAD.
//
// The language server does NOT apply changes itself.
type FolderFixFileResult struct {
	WorkspacePath string `json:"workspacePath"` // passed-folder-prefixed path (remap basis for daemon)
	WorktreePath  string `json:"worktreePath"`  // finished file in worktree (copy source); empty for deletions
	Diff          string `json:"diff"`          // raw unified git diff HEAD -> worktree for this file
}

// FolderFixResult is the executeCommand response body for
// snyk.remediationAgent.fixFolder. Files is empty (never nil) when the fix
// produced no changes, so JSON always serializes as [] not null.
type FolderFixResult struct {
	Files []FolderFixFileResult `json:"files"`
}
