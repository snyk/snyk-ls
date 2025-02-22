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

package code

import (
	"github.com/erni27/imcache"
	"golang.org/x/exp/slices"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

var _ snyk.CacheProvider = (*Scanner)(nil)

func (sc *Scanner) addToCache(results []types.Issue) {
	sc.issueCache.RemoveExpired()
	for _, issue := range results {
		cachedIssues, present := sc.issueCache.Get(issue.GetAffectedFilePath())
		if present {
			cachedIssues = append(cachedIssues, issue)
			cachedIssues = sc.deduplicate(cachedIssues)
			sc.issueCache.Set(issue.GetAffectedFilePath(), cachedIssues, imcache.WithDefaultExpiration())
		} else {
			sc.issueCache.Set(issue.GetAffectedFilePath(), []types.Issue{issue}, imcache.WithDefaultExpiration())
		}
	}
}

func (sc *Scanner) removeFromCache(scanned map[types.FilePath]bool) {
	for path := range scanned {
		sc.ClearIssues(path)
	}
}

func (sc *Scanner) deduplicate(issues []types.Issue) []types.Issue {
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

func (sc *Scanner) Issue(key string) types.Issue {
	for _, issues := range sc.issueCache.GetAll() {
		for _, issue := range issues {
			if issue.GetAdditionalData().GetKey() == key {
				return issue
			}
		}
	}
	return nil
}

func (sc *Scanner) Issues() snyk.IssuesByFile {
	return sc.issueCache.GetAll()
}

func (sc *Scanner) IssuesForFile(path types.FilePath) []types.Issue {
	issues, found := sc.issueCache.Get(path)
	if !found {
		return []types.Issue{}
	}
	return issues
}

func (sc *Scanner) IssuesForRange(path types.FilePath, r types.Range) []types.Issue {
	issues, found := sc.issueCache.Get(path)
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

func (sc *Scanner) IsProviderFor(issueType product.FilterableIssueType) bool {
	return slices.Contains(sc.Product().ToFilterableIssueType(), issueType)
}

func (sc *Scanner) Clear() {
	for path := range sc.Issues() {
		sc.ClearIssues(path)
	}
}

func (sc *Scanner) ClearIssues(path types.FilePath) {
	if sc.cacheRemovalHandler != nil {
		sc.cacheRemovalHandler(path)
	}
	sc.issueCache.Remove(path)
}

func (sc *Scanner) RegisterCacheRemovalHandler(handler func(path types.FilePath)) {
	sc.cacheRemovalHandler = handler
}
