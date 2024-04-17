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

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
)

func (sc *Scanner) addToCache(results []snyk.Issue) {
	sc.issueCache.RemoveExpired()
	for _, issue := range results {
		cachedIssues, present := sc.issueCache.Get(issue.AffectedFilePath)
		if present {
			cachedIssues = append(cachedIssues, issue)
			cachedIssues = sc.deduplicate(cachedIssues)
			sc.issueCache.Set(issue.AffectedFilePath, cachedIssues, imcache.WithDefaultExpiration())
		} else {
			sc.issueCache.Set(issue.AffectedFilePath, []snyk.Issue{issue}, imcache.WithDefaultExpiration())
		}
	}
}

func (sc *Scanner) deduplicate(issues []snyk.Issue) []snyk.Issue {
	var deduplicatedSlice []snyk.Issue
	seen := map[string]bool{}
	for _, issue := range issues {
		uniqueID := issue.AdditionalData.GetKey()
		if !seen[uniqueID] {
			seen[uniqueID] = true
			deduplicatedSlice = append(deduplicatedSlice, issue)
		}
	}
	return deduplicatedSlice
}

func (sc *Scanner) IssuesForRange(path string, r snyk.Range) []snyk.Issue {
	issues, found := sc.issueCache.Get(path)
	if !found {
		return []snyk.Issue{}
	}
	var filteredIssues []snyk.Issue
	for _, issue := range issues {
		if issue.Range.Overlaps(r) {
			filteredIssues = append(filteredIssues, issue)
		}
	}
	return filteredIssues
}

func (sc *Scanner) Issue(key string) snyk.Issue {
	for _, issues := range sc.issueCache.GetAll() {
		for _, issue := range issues {
			if issue.AdditionalData.GetKey() == key {
				return issue
			}
		}
	}
	return snyk.Issue{}
}

func (sc *Scanner) removeFromCache(scanned map[string]bool) {
	for path := range scanned {
		sc.ClearIssues(path)
	}
}

func (sc *Scanner) IssuesForFile(path string) []snyk.Issue {
	issues, found := sc.issueCache.Get(path)
	if !found {
		return []snyk.Issue{}
	}
	return issues
}

func (sc *Scanner) Issues() snyk.IssuesByFile {
	return sc.issueCache.GetAll()
}

func (sc *Scanner) IsProviderFor(product product.Product) bool {
	return product == sc.Product()
}

func (sc *Scanner) ClearIssues(path string) {
	if sc.cacheRemovalHandler != nil {
		sc.cacheRemovalHandler(path)
	}
	sc.issueCache.Remove(path)
}

func (sc *Scanner) RegisterCacheRemovalHandler(handler func(path string)) {
	sc.cacheRemovalHandler = handler
}
