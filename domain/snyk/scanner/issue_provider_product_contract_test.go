/*
 * © 2022-2026 Snyk Limited
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

//go:generate go tool github.com/golang/mock/mockgen -source=issue_provider_product_contract_test.go -destination=mock_issue_provider_product_scanner_test.go -package=scanner IssueProviderProductScanner

import (
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/types"
)

// IssueProviderProductScanner is ProductScanner plus IssueProvider (no CachedIssuePaths).
// Used only to generate a gomock for NewDelegatingScanner invariant tests.
type IssueProviderProductScanner interface {
	types.ProductScanner
	snyk.IssueProvider
}
