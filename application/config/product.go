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

package config

import "github.com/snyk/snyk-ls/internal/product"

func (c *Config) IsProductEnabled(p product.Product) bool {
	switch p {
	case product.ProductCode:
		return c.IsSnykCodeEnabled() || c.IsSnykCodeSecurityEnabled()
	case product.ProductOpenSource:
		return c.IsSnykOssEnabled()
	case product.ProductInfrastructureAsCode:
		return c.IsSnykIacEnabled()
	case product.ProductContainer:
		return c.IsSnykContainerEnabled()
	default:
		return false
	}
}

func (c *Config) DisplayableIssueTypes() map[product.FilterableIssueType]bool {
	enabled := make(map[product.FilterableIssueType]bool)
	enabled[product.FilterableIssueTypeOpenSource] = c.IsSnykOssEnabled()

	// Handle backwards compatibility.
	enabled[product.FilterableIssueTypeCodeSecurity] = c.IsSnykCodeEnabled() || c.IsSnykCodeSecurityEnabled()
	enabled[product.FilterableIssueTypeInfrastructureAsCode] = c.IsSnykIacEnabled()
	enabled[product.FilterableIssueTypeContainer] = c.IsSnykContainerEnabled()

	return enabled
}
