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

import "github.com/snyk/snyk-ls/internal/product"

// IssueProvider is an interface that allows to retrieve issues for a given path and range.
// This is used instead of any concrete dependency to allow for easier testing and more flexibility in implementation.
type IssueProvider interface {
	IssuesForFile(path string) []Issue
	IssuesForRange(path string, r Range) []Issue
	Issue(key string) Issue
}

type CacheProvider interface {
	IssueProvider
	IsProviderFor(product product.Product) bool
}
