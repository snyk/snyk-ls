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

// Package issuecache provides a cache for Issue types.
package issuecache

import (
	"github.com/erni27/imcache"
	"github.com/google/uuid"
	"golang.org/x/exp/slices"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/issuecache/backend"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

type IssueCache struct {
	// Cache is the underlying imcache shard when store is a MemoryBackend.
	// Retained so existing tests (and a few call sites) can reach the concrete
	// imcache API. Always keep this pointer in sync with the memory backend via
	// SetCacheForTests; direct assignment without that helper desynchronises
	// store and IssueIndex.
	Cache *imcache.Cache[types.FilePath, []types.Issue]
	store backend.StorageBackend

	cacheRemovalHandler func(path types.FilePath)
	product             product.Product
	// index is a lightweight, always-resident projection of every cached issue.
	// Issue(key), CachedPaths, and Clear use it to avoid full-store walks on bolt.
	index *IssueIndex
	side  *codeActionsSide
}

func NewIssueCache(p product.Product) *IssueCache {
	mb := backend.NewDefaultMemoryBackend()
	return &IssueCache{
		product: p,
		Cache:   mb.Imcache(),
		store:   mb,
		index:   NewIssueIndex(),
		side:    newCodeActionsSide(),
	}
}

// SetCacheForTests swaps the imcache shard and rebuilds the in-memory index.
// Use this instead of assigning IssueCache.Cache directly so StorageBackend and
// IssueIndex stay aligned (cp11r.3).
func (c *IssueCache) SetCacheForTests(ic *imcache.Cache[types.FilePath, []types.Issue]) {
	c.Cache = ic
	c.store = backend.NewMemoryBackend(ic)
	c.index = NewIssueIndex()
	c.side = newCodeActionsSide()
}

// Index returns the in-memory issue index. Exposed for callers that will read
// by key / path / code-action UUID without materializing the rich body. See
// IDE-1940 cp11r.
func (c *IssueCache) Index() *IssueIndex {
	return c.index
}

func (c *IssueCache) AddToCache(results []types.Issue) {
	c.store.RemoveExpired()
	if len(results) == 0 {
		return
	}
	byPath := make(map[types.FilePath][]types.Issue)
	for _, issue := range results {
		p := issue.GetAffectedFilePath()
		byPath[p] = append(byPath[p], issue)
	}
	for path, batch := range byPath {
		c.addToCacheForPath(path, batch)
	}
}

func (c *IssueCache) addToCacheForPath(path types.FilePath, batch []types.Issue) {
	existingStripped, hadExisting := c.store.Get(path)
	var merged []types.Issue
	if hadExisting && len(existingStripped) > 0 {
		merged = append(c.materializeIssues(existingStripped), batch...)
	} else {
		merged = batch
	}
	merged = c.deduplicate(merged)

	newKeys := make(map[string]struct{}, len(merged))
	for _, iss := range merged {
		if k := issueKey(iss); k != "" {
			newKeys[k] = struct{}{}
		}
	}
	for _, k := range c.index.KeysForPath(path) {
		if _, keep := newKeys[k]; !keep {
			c.side.evictKey(k)
			c.index.RemoveByKey(k)
		}
	}

	stripped := make([]types.Issue, len(merged))
	for i, iss := range merged {
		c.side.replaceFromIssue(iss)
		c.index.UpsertFromIssue(iss)
		stripped[i] = stripCodeActionsClone(iss)
	}
	c.store.Set(path, stripped)
}

func (c *IssueCache) ClearByIssueSlice(results []types.Issue) {
	c.store.RemoveExpired()
	unique := make(map[types.FilePath]struct{}, len(results))
	for _, issue := range results {
		unique[issue.GetAffectedFilePath()] = struct{}{}
	}
	for path := range unique {
		if _, present := c.store.Get(path); present {
			c.ClearIssues(path)
		}
	}
}

func (c *IssueCache) RemoveFromCache(scanned map[types.FilePath]bool) {
	for path := range scanned {
		c.ClearIssues(path)
	}
}

func (c *IssueCache) deduplicate(issues []types.Issue) []types.Issue {
	var deduplicatedSlice []types.Issue
	seen := map[string]bool{}
	for _, issue := range issues {
		uniqueID := issueKey(issue)
		if !seen[uniqueID] {
			seen[uniqueID] = true
			deduplicatedSlice = append(deduplicatedSlice, issue)
		}
	}
	return deduplicatedSlice
}

func (c *IssueCache) Issue(key string) types.Issue {
	if key == "" {
		return nil
	}
	entry, ok := c.index.EntryByKey(key)
	if !ok {
		return nil
	}
	issues, found := c.store.Get(entry.Path)
	if !found {
		return nil
	}
	if len(issues) == 1 {
		if issueKey(issues[0]) == key {
			return c.mergeCodeActionsCopy(issues[0])
		}
		return nil
	}
	for _, issue := range issues {
		if issueKey(issue) == key {
			return c.mergeCodeActionsCopy(issue)
		}
	}
	return nil
}

// IssueByCodeActionUUID resolves a code-action UUID to a rich issue via T1 index (cp11r.6).
func (c *IssueCache) IssueByCodeActionUUID(id uuid.UUID) types.Issue {
	if id == uuid.Nil {
		return nil
	}
	key, ok := c.index.KeyForActionUUID(id)
	if !ok {
		return nil
	}
	return c.Issue(key)
}

// CachedPaths returns every file path with at least one cached issue (T1 index; no JSON decode).
func (c *IssueCache) CachedPaths() []types.FilePath {
	return c.index.Paths()
}

func (c *IssueCache) Issues() snyk.IssuesByFile {
	raw := c.store.GetAll()
	out := make(snyk.IssuesByFile, len(raw))
	for path, issues := range raw {
		out[path] = c.materializeIssues(issues)
	}
	return out
}

func (c *IssueCache) IssuesForFile(path types.FilePath) []types.Issue {
	issues, found := c.store.Get(path)
	if !found {
		return []types.Issue{}
	}
	return c.materializeIssues(issues)
}

func (c *IssueCache) IssuesForRange(path types.FilePath, r types.Range) []types.Issue {
	issues, found := c.store.Get(path)
	if !found {
		return []types.Issue{}
	}
	issues = c.materializeIssues(issues)
	var filteredIssues []types.Issue
	// Linear scan: issues are not sorted by range; binary search would require a
	// sorted view and overlapping-interval logic — not a win for typical k≪100 per file.
	for _, issue := range issues {
		if issue.GetRange().Overlaps(r) {
			filteredIssues = append(filteredIssues, issue)
		}
	}
	return filteredIssues
}

func (c *IssueCache) IsProviderFor(issueType product.FilterableIssueType) bool {
	return slices.Contains(c.product.ToFilterableIssueType(), issueType)
}

func (c *IssueCache) Clear() {
	for _, path := range c.CachedPaths() {
		c.ClearIssues(path)
	}
}

// ClearIssuesByPath clears issues for a given path, which can be a file or folder.
// If a folder path is given, all cached issues for files within that folder are cleared.
func (c *IssueCache) ClearIssuesByPath(path types.FilePath) {
	// Collect paths first, then clear after iteration. BoltBackend.ForEachPath runs
	// under a read transaction; ClearIssues → Remove must not run inside that callback.
	var toClear []types.FilePath
	c.store.ForEachPath(func(cachedPath types.FilePath) bool {
		if uri.FolderContains(path, cachedPath) {
			toClear = append(toClear, cachedPath)
		}
		return true
	})
	for _, p := range toClear {
		c.ClearIssues(p)
	}
}

func (c *IssueCache) ClearIssues(path types.FilePath) {
	if c.cacheRemovalHandler != nil {
		c.cacheRemovalHandler(path)
	}
	c.side.evictPath(c.index, path)
	c.store.Remove(path)
	c.index.RemoveByPath(path)
}

func (c *IssueCache) RegisterCacheRemovalHandler(handler func(path types.FilePath)) {
	c.cacheRemovalHandler = handler
}

var (
	_ snyk.CachedIssuePaths              = (*IssueCache)(nil)
	_ snyk.IssueByCodeActionUUIDProvider = (*IssueCache)(nil)
)
