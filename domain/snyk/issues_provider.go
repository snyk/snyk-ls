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

package snyk

import (
	"fmt"

	"github.com/snyk/snyk-ls/internal/product"
)

type IssuesByFile map[string][]Issue

func (f IssuesByFile) SeverityCountsAsString(critical, high, medium, low int) string {
	var severityCounts string
	if critical > 0 {
		severityCounts += fmt.Sprintf("%d critical", critical)
	}

	if high > 0 {
		if !isFirstSeverity(severityCounts) {
			severityCounts += ","
		}
		severityCounts += fmt.Sprintf("%d high", high)
	}

	if medium > 0 {
		if !isFirstSeverity(severityCounts) {
			severityCounts += ","
		}
		severityCounts += fmt.Sprintf("%d medium", medium)
	}

	if low > 0 {
		if !isFirstSeverity(severityCounts) {
			severityCounts += ","
		}
		severityCounts += fmt.Sprintf("%d low", low)
	}

	return severityCounts
}

func (f IssuesByFile) SeverityCounts() (total, critical, high, medium, low int) {
	for _, issues := range f {
		for _, issue := range issues {
			total++
			switch issue.Severity {
			case Critical:
				critical++
			case High:
				high++
			case Medium:
				medium++
			case Low:
				low++
			}
		}
	}
	return total, critical, high, medium, low
}

func (f IssuesByFile) FixableCount() int {
	var fixableCount int
	for _, issues := range f {
		for _, issue := range issues {
			if issue.AdditionalData.IsFixable() {
				fixableCount++
			}
		}
	}
	return fixableCount
}

func isFirstSeverity(severityCounts string) bool {
	return len(severityCounts) > 0
}

type ProductIssuesByFile map[product.Product]IssuesByFile

// IssueProvider is an interface that allows to retrieve issues for a given path and range.
// This is used instead of any concrete dependency to allow for easier testing and more flexibility in implementation.
type IssueProvider interface {
	IssuesForFile(path string) []Issue
	IssuesForRange(path string, r Range) []Issue
	Issue(key string) Issue
	Issues() IssuesByFile
}

type CacheProvider interface {
	IssueProvider
	IsProviderFor(issueType product.FilterableIssueType) bool
	Clear()
	ClearIssues(path string)
	RegisterCacheRemovalHandler(handler func(path string))
}
