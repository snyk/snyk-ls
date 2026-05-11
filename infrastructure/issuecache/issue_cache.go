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
	"sync"
	"sync/atomic"

	"github.com/erni27/imcache"
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

	// mu serializes the Get-Modify-Set pattern in AddToCache so concurrent
	// scans for overlapping paths cannot silently overwrite each other's issues.
	mu                  sync.Mutex
	cacheRemovalHandler func(path types.FilePath)
	product             product.Product
	// index is a lightweight, always-resident projection of every cached issue.
	// It is additive today: no caller reads it yet. Checkpoints cp11r.3-7 will
	// wire the rich-payload reads through a StorageBackend and then use the
	// index as the primary identity surface. Maintaining it now keeps the
	// groundwork small and lets tests lock in consistency before the backend
	// swap lands. See IDE-1940_implementation_plan.md cp11r.
	//
	// atomic.Pointer is used so Index() reads and rebuildIndexFromStore writes
	// are race-free without requiring the caller to hold mu.
	index atomic.Pointer[IssueIndex]
}

func NewIssueCache(p product.Product) *IssueCache {
	mb := backend.NewDefaultMemoryBackend()
	c := &IssueCache{
		product: p,
		Cache:   mb.Imcache(),
		store:   mb,
	}
	c.index.Store(NewIssueIndex())
	return c
}

// SetCacheForTests swaps the imcache shard and rebuilds the in-memory index.
// Use this instead of assigning IssueCache.Cache directly so StorageBackend and
// IssueIndex stay aligned (cp11r.3).
func (c *IssueCache) SetCacheForTests(ic *imcache.Cache[types.FilePath, []types.Issue]) {
	c.Cache = ic
	c.store = backend.NewMemoryBackend(ic)
	c.rebuildIndexFromStore()
}

// Index returns the in-memory issue index. Exposed for callers that will read
// by key / path / code-action UUID without materializing the rich body. See
// IDE-1940 cp11r.
func (c *IssueCache) Index() *IssueIndex {
	return c.index.Load()
}

func (c *IssueCache) AddToCache(results []types.Issue) {
	c.store.RemoveExpired()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneExpiredFromIndex()
	idx := c.index.Load()
	for _, issue := range results {
		cachedIssues, present := c.store.Get(issue.GetAffectedFilePath())
		if present {
			cachedIssues = append(cachedIssues, issue)
			cachedIssues = c.deduplicate(cachedIssues)
			c.store.Set(issue.GetAffectedFilePath(), cachedIssues)
		} else {
			c.store.Set(issue.GetAffectedFilePath(), []types.Issue{issue})
		}
		idx.UpsertFromIssue(issue)
	}
}

func (c *IssueCache) ClearByIssueSlice(results []types.Issue) {
	c.store.RemoveExpired()
	for _, issue := range results {
		affectedFilePath := issue.GetAffectedFilePath()
		if _, present := c.store.Get(affectedFilePath); present {
			c.ClearIssues(affectedFilePath)
		}
	}
}

// pruneExpiredFromIndex removes index entries whose paths are no longer present
// in the store. Must be called with c.mu held to prevent a TOCTOU with a
// concurrent AddToCache that could re-add a path between the store.Get check
// and the idx.RemoveByPath call. O(P) path-existence checks where P is the
// number of indexed paths — typically much smaller than the total issue count.
func (c *IssueCache) pruneExpiredFromIndex() {
	idx := c.index.Load()
	for _, path := range idx.Paths() {
		if _, found := c.store.Get(path); !found {
			idx.RemoveByPath(path)
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
		uniqueID := issue.GetAdditionalData().GetKey()
		if !seen[uniqueID] {
			seen[uniqueID] = true
			deduplicatedSlice = append(deduplicatedSlice, issue)
		}
	}
	return deduplicatedSlice
}

func (c *IssueCache) Issue(key string) types.Issue {
	for _, issues := range c.store.GetAll() {
		for _, issue := range issues {
			if issue.GetAdditionalData().GetKey() == key {
				return issue
			}
		}
	}
	return nil
}

func (c *IssueCache) Issues() snyk.IssuesByFile {
	return c.store.GetAll()
}

func (c *IssueCache) IssuesForFile(path types.FilePath) []types.Issue {
	issues, found := c.store.Get(path)
	if !found {
		return []types.Issue{}
	}
	return issues
}

func (c *IssueCache) IssuesForRange(path types.FilePath, r types.Range) []types.Issue {
	issues, found := c.store.Get(path)
	if !found {
		return []types.Issue{}
	}
	var filteredIssues []types.Issue
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
	for path := range c.Issues() {
		c.ClearIssues(path)
	}
}

// ClearIssuesByPath clears issues for a given path, which can be a file or folder.
// If a folder path is given, all cached issues for files within that folder are cleared.
func (c *IssueCache) ClearIssuesByPath(path types.FilePath) {
	c.store.ForEachPath(func(cachedPath types.FilePath) bool {
		if uri.FolderContains(path, cachedPath) {
			c.ClearIssues(cachedPath)
		}
		return true
	})
}

func (c *IssueCache) ClearIssues(path types.FilePath) {
	c.mu.Lock()
	c.store.Remove(path)
	c.index.Load().RemoveByPath(path)
	c.mu.Unlock()
	// Handler called outside c.mu: it may send LSP notifications (I/O) and
	// must not re-enter IssueCache methods that acquire the same lock.
	if c.cacheRemovalHandler != nil {
		c.cacheRemovalHandler(path)
	}
}

func (c *IssueCache) rebuildIndexFromStore() {
	index := NewIssueIndex()
	for _, issues := range c.store.GetAll() {
		for _, issue := range issues {
			index.UpsertFromIssue(issue)
		}
	}
	c.index.Store(index)
}

func (c *IssueCache) RegisterCacheRemovalHandler(handler func(path types.FilePath)) {
	c.cacheRemovalHandler = handler
}
