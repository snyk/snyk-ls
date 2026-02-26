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

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/product"
)

func TestProductRegistry_Completeness(t *testing.T) {
	// Every non-unknown product constant must have an entry in the registry.
	nonUnknownProducts := []product.Product{
		product.ProductCode,
		product.ProductOpenSource,
		product.ProductInfrastructureAsCode,
	}

	for _, p := range nonUnknownProducts {
		t.Run(string(p), func(t *testing.T) {
			found := false
			for _, desc := range productRegistry {
				if desc.product == p {
					found = true
					break
				}
			}
			assert.True(t, found, "product %q not found in productRegistry", p)
		})
	}

	t.Run("no extra entries", func(t *testing.T) {
		known := map[product.Product]bool{
			product.ProductCode:                 true,
			product.ProductOpenSource:           true,
			product.ProductInfrastructureAsCode: true,
		}
		for _, desc := range productRegistry {
			assert.True(t, known[desc.product],
				"productRegistry has unexpected product %q", desc.product)
		}
	})
}

func TestProductRegistry_SettingNames(t *testing.T) {
	expectedSettingNames := map[product.Product]string{
		product.ProductCode:                 SettingSnykCodeEnabled,
		product.ProductOpenSource:           SettingSnykOssEnabled,
		product.ProductInfrastructureAsCode: SettingSnykIacEnabled,
	}

	for _, desc := range productRegistry {
		t.Run(string(desc.product), func(t *testing.T) {
			expected, ok := expectedSettingNames[desc.product]
			require.True(t, ok, "no expected setting name for product %q", desc.product)
			assert.Equal(t, expected, desc.settingName,
				"product %q has wrong settingName", desc.product)
		})
	}
}

func TestProductRegistry_Codenames(t *testing.T) {
	expectedCodenames := map[product.Product]string{
		product.ProductCode:                 "code",
		product.ProductOpenSource:           "oss",
		product.ProductInfrastructureAsCode: "iac",
	}

	for _, desc := range productRegistry {
		t.Run(string(desc.product), func(t *testing.T) {
			expected, ok := expectedCodenames[desc.product]
			require.True(t, ok, "no expected codename for product %q", desc.product)
			assert.Equal(t, expected, desc.codename,
				"product %q has wrong codename", desc.product)
		})
	}
}

func TestProductRegistry_FilterableIssueTypes(t *testing.T) {
	expectedTypes := map[product.Product]product.FilterableIssueType{
		product.ProductCode:                 product.FilterableIssueTypeCodeSecurity,
		product.ProductOpenSource:           product.FilterableIssueTypeOpenSource,
		product.ProductInfrastructureAsCode: product.FilterableIssueTypeInfrastructureAsCode,
	}

	for _, desc := range productRegistry {
		t.Run(string(desc.product), func(t *testing.T) {
			expected, ok := expectedTypes[desc.product]
			require.True(t, ok, "no expected filterable issue type for product %q", desc.product)
			assert.Equal(t, expected, desc.filterableIssueType,
				"product %q has wrong filterableIssueType", desc.product)
		})
	}
}
