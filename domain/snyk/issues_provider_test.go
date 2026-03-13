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

func TestProductIssuesByFile_Flatten(t *testing.T) {
	filePath1 := types.FilePath("file1.go")
	filePath2 := types.FilePath("file2.go")
	filePath3 := types.FilePath("file3.go")
	issueA := &Issue{AffectedFilePath: filePath1, Product: product.ProductOpenSource, AdditionalData: OssIssueData{Key: "oss-1"}}
	issueB := &Issue{AffectedFilePath: filePath1, Product: product.ProductCode, AdditionalData: CodeIssueData{Key: "code-1"}}
	issueC := &Issue{AffectedFilePath: filePath2, Product: product.ProductOpenSource, AdditionalData: OssIssueData{Key: "oss-2"}}
	issueD := &Issue{AffectedFilePath: filePath3, Product: product.ProductCode, AdditionalData: CodeIssueData{Key: "code-2"}}

	tests := []struct {
		name                string
		input               ProductIssuesByFile
		expectedIssueCounts map[types.FilePath]int
	}{
		{
			name:                "empty map returns empty",
			input:               ProductIssuesByFile{},
			expectedIssueCounts: nil,
		},
		{
			name: "single product single file one issue",
			input: ProductIssuesByFile{
				product.ProductOpenSource: IssuesByFile{
					filePath1: {issueA},
				},
			},
			expectedIssueCounts: map[types.FilePath]int{
				filePath1: 1,
			},
		},
		{
			name: "multiple products different files",
			input: ProductIssuesByFile{
				product.ProductOpenSource: IssuesByFile{
					filePath2: {issueC},
				},
				product.ProductCode: IssuesByFile{
					filePath3: {issueD},
				},
			},
			expectedIssueCounts: map[types.FilePath]int{
				filePath2: 1,
				filePath3: 1,
			},
		},
		{
			name: "multiple products same file combines issues",
			input: ProductIssuesByFile{
				product.ProductOpenSource: IssuesByFile{
					filePath1: {issueA},
				},
				product.ProductCode: IssuesByFile{
					filePath1: {issueB},
				},
			},
			expectedIssueCounts: map[types.FilePath]int{
				filePath1: 2,
			},
		},
		{
			name: "single product empty issue slice preserved for cleared file",
			input: ProductIssuesByFile{
				product.ProductOpenSource: IssuesByFile{
					filePath1: {},
				},
			},
			expectedIssueCounts: map[types.FilePath]int{
				filePath1: 0,
			},
		},
		{
			name: "multiple products overlapping files and a cleared file",
			input: ProductIssuesByFile{
				product.ProductOpenSource: IssuesByFile{
					filePath1: {issueA},
					filePath2: {},
				},
				product.ProductCode: IssuesByFile{
					filePath1: {issueB},
				},
			},
			expectedIssueCounts: map[types.FilePath]int{
				filePath1: 2,
				filePath2: 0,
			},
		},
		{
			name: "multiple products clearing a file",
			input: ProductIssuesByFile{
				product.ProductOpenSource: IssuesByFile{
					filePath1: {},
				},
				product.ProductCode: IssuesByFile{
					filePath1: {},
				},
			},
			expectedIssueCounts: map[types.FilePath]int{
				filePath1: 0,
			},
		},
		{
			name: "multiple products overlapping files one with issues one clearing the file",
			input: ProductIssuesByFile{
				product.ProductOpenSource: IssuesByFile{
					filePath1: {},
				},
				product.ProductCode: IssuesByFile{
					filePath1: {issueB},
				},
			},
			expectedIssueCounts: map[types.FilePath]int{
				filePath1: 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.Flatten()

			assert.Len(t, result, len(tt.expectedIssueCounts))
			for path, expectedCount := range tt.expectedIssueCounts {
				issues, exists := result[path]
				assert.True(t, exists, "expected file %s in flattened result", path)
				assert.Len(t, issues, expectedCount, "wrong issue count for %s", path)
			}
		})
	}
}
