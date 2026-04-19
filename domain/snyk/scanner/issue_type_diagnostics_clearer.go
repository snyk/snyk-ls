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

package scanner

import (
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

var (
	_ IssueTypeDiagnosticsClearer = (*DelegatingConcurrentScanner)(nil)
	_ IssueTypeDiagnosticsClearer = (*TestScanner)(nil)
)

// IssueTypeDiagnosticsClearer removes cached issues for one filterable issue type without clearing other
// products' issues on the same path (required when a folder scanner aggregates multiple IssueCaches).
type IssueTypeDiagnosticsClearer interface {
	ClearDiagnosticsForIssueType(removedType product.FilterableIssueType, contains func(types.FilePath) bool)
}

func (sc *DelegatingConcurrentScanner) ClearDiagnosticsForIssueType(removedType product.FilterableIssueType, contains func(types.FilePath) bool) {
	for _, productScanner := range sc.scanners {
		cp, ok := productScanner.(snyk.CacheProvider)
		if !ok || !cp.IsProviderFor(removedType) {
			continue
		}
		pl, ok := productScanner.(snyk.CachedIssuePaths)
		if !ok {
			panic("scanner: product scanner is a CacheProvider but not CachedIssuePaths; cannot clear by issue type without full cache read")
		}
		for _, path := range pl.CachedPaths() {
			if contains(path) {
				cp.ClearIssues(path)
			}
		}
	}
}

func (s *TestScanner) ClearDiagnosticsForIssueType(removedType product.FilterableIssueType, contains func(types.FilePath) bool) {
	for _, c := range s.caches() {
		if !c.IsProviderFor(removedType) {
			continue
		}
		for _, path := range c.CachedPaths() {
			if contains(path) {
				c.ClearIssues(path)
			}
		}
	}
}
