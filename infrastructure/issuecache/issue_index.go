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

package issuecache

import (
	"sync"

	"github.com/google/uuid"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

// IssueIndexEntry is the lightweight, always-resident projection of an Issue.
// It carries everything the LSP hot paths (tree view, severity counts, delta,
// didOpen gating, fixCodeIssue UUID dispatch) need without holding on to the
// rich body (FormattedMessage, References, hover HTML, AdditionalData payload,
// CodeAction closures, ...). The rich body lives in a StorageBackend that the
// index points at.
//
// Field selection is deliberately minimal: each byte here stays resident for
// the full session on megaproject scans (N ~ 80 000). Anything that can be
// reconstructed cheaply or reloaded from the backend is left out.
type IssueIndexEntry struct {
	Key             string
	RuleID          string
	GlobalIdentity  string
	Fingerprint     string
	Path            types.FilePath
	Range           types.Range
	Severity        types.Severity
	Product         product.Product
	IssueType       product.FilterableIssueType
	IsIgnored       bool
	IsNew           bool
	CodeActionUUIDs []uuid.UUID
}

// IssueIndex keeps three in-memory lookup tables over IssueIndexEntry values:
//
//   - byKey         issueKey       → entry  (primary)
//   - byFile        filePath       → []keys (per-file enumeration)
//   - byActionUUID  code-action ID → issueKey (fixCodeIssue shortcut)
//
// The index is additive on top of the existing IssueCache. All three maps stay
// in lockstep; every mutation takes the write lock. Readers take the read lock
// and must treat returned slices as read-only snapshots.
type IssueIndex struct {
	mu           sync.RWMutex
	byKey        map[string]IssueIndexEntry
	byFile       map[types.FilePath]map[string]struct{}
	byActionUUID map[uuid.UUID]string
}

// NewIssueIndex returns an empty index. The zero value of IssueIndex is not
// usable (all three maps must be non-nil under the lock).
func NewIssueIndex() *IssueIndex {
	return &IssueIndex{
		byKey:        make(map[string]IssueIndexEntry),
		byFile:       make(map[types.FilePath]map[string]struct{}),
		byActionUUID: make(map[uuid.UUID]string),
	}
}

// Len returns the number of indexed issues.
func (i *IssueIndex) Len() int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.byKey)
}

// Upsert records (or replaces) the entry for entry.Key. The previous entry's
// per-file and code-action cross-references, if any, are removed first so the
// index is always consistent after the call.
func (i *IssueIndex) Upsert(entry IssueIndexEntry) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.removeKeyLocked(entry.Key)
	i.byKey[entry.Key] = entry
	if entry.Path != "" {
		keys, ok := i.byFile[entry.Path]
		if !ok {
			keys = make(map[string]struct{})
			i.byFile[entry.Path] = keys
		}
		keys[entry.Key] = struct{}{}
	}
	for _, id := range entry.CodeActionUUIDs {
		i.byActionUUID[id] = entry.Key
	}
}

// UpsertFromIssue projects an Issue into an IssueIndexEntry and stores it.
func (i *IssueIndex) UpsertFromIssue(issue types.Issue) {
	if issue == nil {
		return
	}
	i.Upsert(issueToIndexEntry(issue))
}

// RemoveByKey drops a single indexed entry and its cross-references.
func (i *IssueIndex) RemoveByKey(key string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.removeKeyLocked(key)
}

// RemoveByPath drops every indexed entry whose Path equals path. Used by
// ClearIssues(path) in the cache layer.
func (i *IssueIndex) RemoveByPath(path types.FilePath) {
	i.mu.Lock()
	defer i.mu.Unlock()
	keys, ok := i.byFile[path]
	if !ok {
		return
	}
	for key := range keys {
		i.removeKeyLocked(key)
	}
}

// Clear drops every indexed entry. Used by Clear() in the cache layer.
func (i *IssueIndex) Clear() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.byKey = make(map[string]IssueIndexEntry)
	i.byFile = make(map[types.FilePath]map[string]struct{})
	i.byActionUUID = make(map[uuid.UUID]string)
}

// EntryByKey returns the entry for key (zero value + false if absent). Safe
// for concurrent use.
func (i *IssueIndex) EntryByKey(key string) (IssueIndexEntry, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	entry, ok := i.byKey[key]
	return entry, ok
}

// KeysForPath returns a freshly-allocated slice of issue keys recorded for
// path. Order is unspecified. Empty path → empty slice.
func (i *IssueIndex) KeysForPath(path types.FilePath) []string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	keys, ok := i.byFile[path]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	return out
}

// Paths returns a freshly-allocated slice of every file path with at least one
// indexed entry. Order is unspecified (map iteration). Callers that need a stable
// order must sort (e.g. tree view sorts paths for display). Sorting paths here
// does not improve bbolt read locality: on-disk keys are sha256(filePath), not
// lexicographic path order. Lookups remain O(1) via byFile / byKey maps; binary
// search is not used — key and path membership are hash-map operations.
func (i *IssueIndex) Paths() []types.FilePath {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]types.FilePath, 0, len(i.byFile))
	for path := range i.byFile {
		out = append(out, path)
	}
	return out
}

// KeyForActionUUID maps a code-action UUID back to the owning issue's key.
// Returns ("", false) when the UUID is not indexed.
func (i *IssueIndex) KeyForActionUUID(id uuid.UUID) (string, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	key, ok := i.byActionUUID[id]
	return key, ok
}

// removeKeyLocked deletes key and its cross-references. Must be called with the
// write lock held.
func (i *IssueIndex) removeKeyLocked(key string) {
	prev, ok := i.byKey[key]
	if !ok {
		return
	}
	delete(i.byKey, key)
	if keys, exists := i.byFile[prev.Path]; exists {
		delete(keys, key)
		if len(keys) == 0 {
			delete(i.byFile, prev.Path)
		}
	}
	for _, id := range prev.CodeActionUUIDs {
		if owner, exists := i.byActionUUID[id]; exists && owner == key {
			delete(i.byActionUUID, id)
		}
	}
}

// issueToIndexEntry projects an Issue into its index entry.
func issueToIndexEntry(issue types.Issue) IssueIndexEntry {
	entry := IssueIndexEntry{
		RuleID:         issue.GetID(),
		GlobalIdentity: issue.GetGlobalIdentity(),
		Fingerprint:    issue.GetFingerprint(),
		Path:           issue.GetAffectedFilePath(),
		Range:          issue.GetRange(),
		Severity:       issue.GetSeverity(),
		Product:        issue.GetProduct(),
		IssueType:      issue.GetFilterableIssueType(),
		IsIgnored:      issue.GetIsIgnored(),
		IsNew:          issue.GetIsNew(),
	}
	if data := issue.GetAdditionalData(); data != nil {
		entry.Key = data.GetKey()
	}
	actions := issue.GetCodeActions()
	if len(actions) > 0 {
		entry.CodeActionUUIDs = make([]uuid.UUID, 0, len(actions))
		for _, action := range actions {
			if id := action.GetUuid(); id != nil {
				entry.CodeActionUUIDs = append(entry.CodeActionUUIDs, *id)
			}
		}
	}
	return entry
}
