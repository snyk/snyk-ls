/*
 * © 2024-2026 Snyk Limited
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

package config

import (
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

// IsProductEnabledForFolder returns whether a product is enabled for a specific folder config,
// considering LDX-Sync org config and user overrides.
func (c *Config) IsProductEnabledForFolder(p product.Product, folderConfig *types.StoredFolderConfig) bool {
	switch p {
	case product.ProductCode:
		return c.IsSnykCodeEnabledForFolder(folderConfig)
	case product.ProductOpenSource:
		return c.IsSnykOssEnabledForFolder(folderConfig)
	case product.ProductInfrastructureAsCode:
		return c.IsSnykIacEnabledForFolder(folderConfig)
	default:
		return false
	}
}

// DisplayableIssueTypesForFolder returns which issue types are enabled for a specific folder config,
// considering LDX-Sync org config and user overrides.
func (c *Config) DisplayableIssueTypesForFolder(folderConfig *types.StoredFolderConfig) map[product.FilterableIssueType]bool {
	enabled := make(map[product.FilterableIssueType]bool)
	enabled[product.FilterableIssueTypeOpenSource] = c.IsSnykOssEnabledForFolder(folderConfig)

	// Handle backwards compatibility.
	enabled[product.FilterableIssueTypeCodeSecurity] = c.IsSnykCodeEnabledForFolder(folderConfig)
	enabled[product.FilterableIssueTypeInfrastructureAsCode] = c.IsSnykIacEnabledForFolder(folderConfig)

	return enabled
}
