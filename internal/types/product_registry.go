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

package types

import "github.com/snyk/snyk-ls/internal/product"

// productDescriptor holds all metadata for a single product.
type productDescriptor struct {
	product             product.Product
	codename            string
	settingName         string
	filterableIssueType product.FilterableIssueType
	isEnabled           func(c ConfigProvider) bool
}

// productRegistry is the single source of truth for product metadata.
// One entry per non-unknown product.
var productRegistry = []productDescriptor{
	{
		product:             product.ProductCode,
		codename:            "code",
		settingName:         SettingSnykCodeEnabled,
		filterableIssueType: product.FilterableIssueTypeCodeSecurity,
		isEnabled:           func(c ConfigProvider) bool { return c.IsSnykCodeEnabled() },
	},
	{
		product:             product.ProductOpenSource,
		codename:            "oss",
		settingName:         SettingSnykOssEnabled,
		filterableIssueType: product.FilterableIssueTypeOpenSource,
		isEnabled:           func(c ConfigProvider) bool { return c.IsSnykOssEnabled() },
	},
	{
		product:             product.ProductInfrastructureAsCode,
		codename:            "iac",
		settingName:         SettingSnykIacEnabled,
		filterableIssueType: product.FilterableIssueTypeInfrastructureAsCode,
		isEnabled:           func(c ConfigProvider) bool { return c.IsSnykIacEnabled() },
	},
}
