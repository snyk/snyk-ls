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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestProductIssuesByFile_FlattenForProduct(t *testing.T) {
	filePath1 := types.FilePath("file1.go")
	filePath2 := types.FilePath("file2.go")
	filePath3 := types.FilePath("file3.go")
	ossIssue1 := &Issue{AffectedFilePath: filePath1, Product: product.ProductOpenSource, AdditionalData: OssIssueData{Key: "oss-1"}}
	ossIssue2 := &Issue{AffectedFilePath: filePath2, Product: product.ProductOpenSource, AdditionalData: OssIssueData{Key: "oss-2"}}
	codeIssue1 := &Issue{AffectedFilePath: filePath1, Product: product.ProductCode, AdditionalData: CodeIssueData{Key: "code-1"}}
	codeIssue2 := &Issue{AffectedFilePath: filePath3, Product: product.ProductCode, AdditionalData: CodeIssueData{Key: "code-2"}}

	tests := []struct {
		name                string
		input               ProductIssuesByFile
		mainProduct         product.Product
		expectedIssueCounts map[types.FilePath]int
	}{
		{
			name:                "empty map returns empty",
			input:               ProductIssuesByFile{},
			mainProduct:         product.ProductOpenSource,
			expectedIssueCounts: nil,
		},
		{
			name: "single product single file one issue",
			input: ProductIssuesByFile{
				product.ProductOpenSource: IssuesByFile{
					filePath1: {ossIssue1},
				},
			},
			mainProduct: product.ProductOpenSource,
			expectedIssueCounts: map[types.FilePath]int{
				filePath1: 1,
			},
		},
		{
			name: "multiple products same file combines issues",
			input: ProductIssuesByFile{
				product.ProductOpenSource: IssuesByFile{
					filePath1: {ossIssue1},
				},
				product.ProductCode: IssuesByFile{
					filePath1: {codeIssue1},
				},
			},
			mainProduct: product.ProductOpenSource,
			expectedIssueCounts: map[types.FilePath]int{
				filePath1: 2,
			},
		},
		{
			name: "other product file not in main product is excluded",
			input: ProductIssuesByFile{
				product.ProductOpenSource: IssuesByFile{
					filePath1: {ossIssue1},
				},
				product.ProductCode: IssuesByFile{
					filePath3: {codeIssue2},
				},
			},
			mainProduct: product.ProductOpenSource,
			expectedIssueCounts: map[types.FilePath]int{
				filePath1: 1,
			},
		},
		{
			name: "main product cleared file still picks up other products issues",
			input: ProductIssuesByFile{
				product.ProductOpenSource: IssuesByFile{
					filePath1: {},
				},
				product.ProductCode: IssuesByFile{
					filePath1: {codeIssue1},
				},
			},
			mainProduct: product.ProductOpenSource,
			expectedIssueCounts: map[types.FilePath]int{
				filePath1: 1,
			},
		},
		{
			name: "both products clearing same file",
			input: ProductIssuesByFile{
				product.ProductOpenSource: IssuesByFile{
					filePath1: {},
				},
				product.ProductCode: IssuesByFile{
					filePath1: {},
				},
			},
			mainProduct: product.ProductOpenSource,
			expectedIssueCounts: map[types.FilePath]int{
				filePath1: 0,
			},
		},
		{
			name: "multiple files some overlapping some not",
			input: ProductIssuesByFile{
				product.ProductOpenSource: IssuesByFile{
					filePath1: {ossIssue1},
					filePath2: {ossIssue2},
				},
				product.ProductCode: IssuesByFile{
					filePath1: {codeIssue1},
					filePath3: {codeIssue2},
				},
			},
			mainProduct: product.ProductOpenSource,
			expectedIssueCounts: map[types.FilePath]int{
				filePath1: 2,
				filePath2: 1,
			},
		},
		{
			name: "switching main product changes which files are included",
			input: ProductIssuesByFile{
				product.ProductOpenSource: IssuesByFile{
					filePath1: {ossIssue1},
					filePath2: {ossIssue2},
				},
				product.ProductCode: IssuesByFile{
					filePath1: {codeIssue1},
					filePath3: {codeIssue2},
				},
			},
			mainProduct: product.ProductCode,
			expectedIssueCounts: map[types.FilePath]int{
				filePath1: 2,
				filePath3: 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.AggregateFromAllProducts(tt.mainProduct)

			assert.Len(t, result, len(tt.expectedIssueCounts))
			for path, expectedCount := range tt.expectedIssueCounts {
				issues, exists := result[path]
				assert.True(t, exists, "expected file %s in flattened result", path)
				assert.Len(t, issues, expectedCount, "wrong issue count for %s", path)
			}
		})
	}
}
