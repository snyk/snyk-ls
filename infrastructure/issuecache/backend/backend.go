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

// Package backend abstracts where rich Issue payloads live (IDE-1940 cp11r).
// The default implementation is MemoryBackend (imcache). A BoltBackend will
// land in cp11r.4; IssueIndex stays in the parent package and is updated on
// every mutation regardless of backend.
package backend

import (
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/types"
)

// StorageBackend is the narrow surface IssueCache needs for per-file issue
// storage. Folder-scoped disk keys (Bolt) will extend the constructors in
// cp11r.4; the memory implementation is path-keyed only, matching today's
// IssueCache semantics (one IssueCache instance per product scanner).
type StorageBackend interface {
	RemoveExpired()
	Get(path types.FilePath) ([]types.Issue, bool)
	Set(path types.FilePath, issues []types.Issue)
	GetAll() snyk.IssuesByFile
	Remove(path types.FilePath)
	// ForEachPath visits every file path that currently has at least one cached
	// issue. Used by ClearIssuesByPath and Clear. Iteration order is undefined.
	ForEachPath(fn func(path types.FilePath) bool)
	Close() error
}
