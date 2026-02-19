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

package issuecache

import (
	"time"

	"github.com/erni27/imcache"
	"golang.org/x/exp/slices"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

type IssueCache struct {
	Cache               *imcache.Cache[types.FilePath, []types.Issue]
	cacheRemovalHandler func(path types.FilePath)
	product             product.Product
}

func NewIssueCache(p product.Product) *IssueCache {
	return &IssueCache{
		product: p,
		Cache: imcache.New[types.FilePath, []types.Issue](
			imcache.WithDefaultExpirationOption[types.FilePath, []types.Issue](time.Hour * 12),
		),
	}
}

func (c *IssueCache) AddToCache(results []types.Issue) {
	c.Cache.RemoveExpired()
	for _, issue := range results {
		cachedIssues, present := c.Cache.Get(issue.GetAffectedFilePath())
		if present {
			cachedIssues = append(cachedIssues, issue)
			cachedIssues = c.deduplicate(cachedIssues)
			c.Cache.Set(issue.GetAffectedFilePath(), cachedIssues, imcache.WithDefaultExpiration())
		} else {
			c.Cache.Set(issue.GetAffectedFilePath(), []types.Issue{issue}, imcache.WithDefaultExpiration())
		}
	}
}

func (c *IssueCache) ClearByIssueSlice(results []types.Issue) {
	c.Cache.RemoveExpired()
	for _, issue := range results {
		affectedFilePath := issue.GetAffectedFilePath()
		if _, present := c.Cache.Get(affectedFilePath); present {
			c.ClearIssues(affectedFilePath)
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
	for _, issues := range c.Cache.GetAll() {
		for _, issue := range issues {
			if issue.GetAdditionalData().GetKey() == key {
				return issue
			}
		}
	}
	return nil
}

func (c *IssueCache) Issues() snyk.IssuesByFile {
	return c.Cache.GetAll()
}

func (c *IssueCache) IssuesForFile(path types.FilePath) []types.Issue {
	issues, found := c.Cache.Get(path)
	if !found {
		return []types.Issue{}
	}
	return issues
}

func (c *IssueCache) IssuesForRange(path types.FilePath, r types.Range) []types.Issue {
	issues, found := c.Cache.Get(path)
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

func (c *IssueCache) ClearIssues(path types.FilePath) {
	if c.cacheRemovalHandler != nil {
		c.cacheRemovalHandler(path)
	}
	c.Cache.Remove(path)
}

func (c *IssueCache) RegisterCacheRemovalHandler(handler func(path types.FilePath)) {
	c.cacheRemovalHandler = handler
}
