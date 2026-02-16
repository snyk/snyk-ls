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

package treeview

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func TestBuildTree_EmptyWorkspace_ReturnsEmptyNodes(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockWorkspace.EXPECT().Folders().Return(nil)

	builder := NewTreeBuilder()
	data := builder.BuildTree(mockWorkspace)

	assert.Empty(t, data.Nodes)
	assert.False(t, data.MultiRoot)
}

func TestBuildTree_NoFolders_ReturnsEmptyNodes(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockWorkspace := mock_types.NewMockWorkspace(ctrl)
	mockWorkspace.EXPECT().Folders().Return([]types.Folder{})

	builder := NewTreeBuilder()
	data := builder.BuildTree(mockWorkspace)

	assert.Empty(t, data.Nodes)
}

func TestBuildTree_SingleFolder_SingleProduct_SingleFile_SingleIssue(t *testing.T) {
	filePath := types.FilePath("/project/src/main.go")
	issue := testutil.NewMockIssue("issue-1", filePath)
	issue.Product = product.ProductCode
	issue.Severity = types.High
	issue.AdditionalData = &snyk.CodeIssueData{
		Key:   "key-1",
		Title: "SQL Injection",
	}

	issuesByFile := snyk.IssuesByFile{filePath: []types.Issue{issue}}
	supportedTypes := map[product.FilterableIssueType]bool{
		product.FilterableIssueTypeCodeSecurity: true,
	}

	builder := NewTreeBuilder()
	data := builder.BuildTreeFromFolderData([]FolderData{
		{
			FolderPath:          "/project",
			FolderName:          "project",
			SupportedIssueTypes: supportedTypes,
			AllIssues:           issuesByFile,
			FilteredIssues:      issuesByFile,
		},
	})

	assert.False(t, data.MultiRoot)
	// Single folder → no folder node; directly product roots
	require.Equal(t, 1, len(data.Nodes), "should have 1 product root (Code)")
	productNode := data.Nodes[0]
	assert.Equal(t, NodeTypeProduct, productNode.Type)
	assert.Equal(t, product.ProductCode, productNode.Product)

	// Product should have file children
	require.GreaterOrEqual(t, len(productNode.Children), 1, "product should have at least 1 file child")
	fileNode := findChildByType(productNode.Children, NodeTypeFile)
	require.NotNil(t, fileNode, "should have a file node")
	assert.Contains(t, fileNode.Label, "main.go")

	// File should have issue children
	require.Equal(t, 1, len(fileNode.Children))
	issueNode := fileNode.Children[0]
	assert.Equal(t, NodeTypeIssue, issueNode.Type)
	assert.Equal(t, types.High, issueNode.Severity)
}

func TestBuildTree_MultiFolder_GroupsByFolder(t *testing.T) {
	builder := NewTreeBuilder()

	filePath1 := types.FilePath("/project-a/main.go")
	issue1 := testutil.NewMockIssue("issue-1", filePath1)
	issue1.Product = product.ProductOpenSource

	filePath2 := types.FilePath("/project-b/app.go")
	issue2 := testutil.NewMockIssue("issue-2", filePath2)
	issue2.Product = product.ProductOpenSource

	supportedTypes := map[product.FilterableIssueType]bool{
		product.FilterableIssueTypeOpenSource: true,
	}

	data := builder.BuildTreeFromFolderData([]FolderData{
		{
			FolderPath:          "/project-a",
			FolderName:          "project-a",
			SupportedIssueTypes: supportedTypes,
			AllIssues:           snyk.IssuesByFile{filePath1: {issue1}},
			FilteredIssues:      snyk.IssuesByFile{filePath1: {issue1}},
		},
		{
			FolderPath:          "/project-b",
			FolderName:          "project-b",
			SupportedIssueTypes: supportedTypes,
			AllIssues:           snyk.IssuesByFile{filePath2: {issue2}},
			FilteredIssues:      snyk.IssuesByFile{filePath2: {issue2}},
		},
	})

	assert.True(t, data.MultiRoot, "multi-root workspace should be flagged")
	require.Equal(t, 2, len(data.Nodes), "should have 2 folder-level nodes")
	assert.Equal(t, NodeTypeFolder, data.Nodes[0].Type)
	assert.Equal(t, NodeTypeFolder, data.Nodes[1].Type)
}

func TestBuildTree_SortIssuesBySeverity(t *testing.T) {
	builder := NewTreeBuilder()

	filePath := types.FilePath("/project/main.go")
	issueLow := testutil.NewMockIssueWithSeverity("low-1", filePath, types.Low)
	issueLow.Product = product.ProductCode
	issueLow.AdditionalData = &snyk.CodeIssueData{Key: "k1", Title: "Low Issue"}

	issueCrit := testutil.NewMockIssueWithSeverity("crit-1", filePath, types.Critical)
	issueCrit.Product = product.ProductCode
	issueCrit.AdditionalData = &snyk.CodeIssueData{Key: "k2", Title: "Critical Issue"}

	issueMed := testutil.NewMockIssueWithSeverity("med-1", filePath, types.Medium)
	issueMed.Product = product.ProductCode
	issueMed.AdditionalData = &snyk.CodeIssueData{Key: "k3", Title: "Medium Issue"}

	supportedTypes := map[product.FilterableIssueType]bool{
		product.FilterableIssueTypeCodeSecurity: true,
	}
	issues := snyk.IssuesByFile{filePath: {issueLow, issueCrit, issueMed}}

	data := builder.BuildTreeFromFolderData([]FolderData{
		{
			FolderPath:          "/project",
			FolderName:          "project",
			SupportedIssueTypes: supportedTypes,
			AllIssues:           issues,
			FilteredIssues:      issues,
		},
	})

	require.Equal(t, 1, len(data.Nodes))
	productNode := data.Nodes[0]
	fileNode := findChildByType(productNode.Children, NodeTypeFile)
	require.NotNil(t, fileNode)
	require.Equal(t, 3, len(fileNode.Children))

	// Issues sorted: Critical first, then High, Medium, Low
	assert.Equal(t, types.Critical, fileNode.Children[0].Severity)
	assert.Equal(t, types.Medium, fileNode.Children[1].Severity)
	assert.Equal(t, types.Low, fileNode.Children[2].Severity)
}

func TestBuildTree_SortFilesAlphabetically(t *testing.T) {
	builder := NewTreeBuilder()

	fileZ := types.FilePath("/project/z_file.go")
	fileA := types.FilePath("/project/a_file.go")
	issueZ := testutil.NewMockIssue("z-1", fileZ)
	issueZ.Product = product.ProductOpenSource
	issueA := testutil.NewMockIssue("a-1", fileA)
	issueA.Product = product.ProductOpenSource

	supportedTypes := map[product.FilterableIssueType]bool{
		product.FilterableIssueTypeOpenSource: true,
	}
	issues := snyk.IssuesByFile{fileZ: {issueZ}, fileA: {issueA}}

	data := builder.BuildTreeFromFolderData([]FolderData{
		{
			FolderPath:          "/project",
			FolderName:          "project",
			SupportedIssueTypes: supportedTypes,
			AllIssues:           issues,
			FilteredIssues:      issues,
		},
	})

	require.Equal(t, 1, len(data.Nodes))
	productNode := data.Nodes[0]
	fileNodes := filterChildrenByType(productNode.Children, NodeTypeFile)
	require.Equal(t, 2, len(fileNodes))
	assert.Contains(t, fileNodes[0].Label, "a_file.go")
	assert.Contains(t, fileNodes[1].Label, "z_file.go")
}

func TestBuildTree_IgnoredIssue_FlaggedOnNode(t *testing.T) {
	builder := NewTreeBuilder()

	filePath := types.FilePath("/project/main.go")
	issue := testutil.NewMockIssueWithIgnored("ign-1", filePath, true)
	issue.Product = product.ProductOpenSource

	supportedTypes := map[product.FilterableIssueType]bool{
		product.FilterableIssueTypeOpenSource: true,
	}
	issues := snyk.IssuesByFile{filePath: {issue}}

	data := builder.BuildTreeFromFolderData([]FolderData{
		{
			FolderPath:          "/project",
			FolderName:          "project",
			SupportedIssueTypes: supportedTypes,
			AllIssues:           issues,
			FilteredIssues:      issues,
		},
	})

	productNode := data.Nodes[0]
	fileNode := findChildByType(productNode.Children, NodeTypeFile)
	require.NotNil(t, fileNode)
	require.Equal(t, 1, len(fileNode.Children))
	assert.True(t, fileNode.Children[0].IsIgnored)
}

func TestBuildTree_MultipleProducts_SeparateRoots(t *testing.T) {
	builder := NewTreeBuilder()

	filePath := types.FilePath("/project/main.go")
	codeIssue := testutil.NewMockIssue("code-1", filePath)
	codeIssue.Product = product.ProductCode
	codeIssue.AdditionalData = &snyk.CodeIssueData{Key: "k1", Title: "Code Issue"}

	ossIssue := testutil.NewMockIssue("oss-1", filePath)
	ossIssue.Product = product.ProductOpenSource

	supportedTypes := map[product.FilterableIssueType]bool{
		product.FilterableIssueTypeCodeSecurity: true,
		product.FilterableIssueTypeOpenSource:   true,
	}
	issues := snyk.IssuesByFile{filePath: {codeIssue, ossIssue}}

	data := builder.BuildTreeFromFolderData([]FolderData{
		{
			FolderPath:          "/project",
			FolderName:          "project",
			SupportedIssueTypes: supportedTypes,
			AllIssues:           issues,
			FilteredIssues:      issues,
		},
	})

	// Should have separate product roots
	require.GreaterOrEqual(t, len(data.Nodes), 2)
	productTypes := make(map[product.Product]bool)
	for _, node := range data.Nodes {
		if node.Type == NodeTypeProduct {
			productTypes[node.Product] = true
		}
	}
	assert.True(t, productTypes[product.ProductCode], "should have Code product root")
	assert.True(t, productTypes[product.ProductOpenSource], "should have OSS product root")
}

func TestBuildTree_ProductDescription_ContainsIssueCount(t *testing.T) {
	builder := NewTreeBuilder()

	filePath := types.FilePath("/project/main.go")
	issue1 := testutil.NewMockIssue("oss-1", filePath)
	issue1.Product = product.ProductOpenSource
	issue2 := testutil.NewMockIssue("oss-2", filePath)
	issue2.Product = product.ProductOpenSource

	supportedTypes := map[product.FilterableIssueType]bool{
		product.FilterableIssueTypeOpenSource: true,
	}
	issues := snyk.IssuesByFile{filePath: {issue1, issue2}}

	data := builder.BuildTreeFromFolderData([]FolderData{
		{
			FolderPath:          "/project",
			FolderName:          "project",
			SupportedIssueTypes: supportedTypes,
			AllIssues:           issues,
			FilteredIssues:      issues,
		},
	})

	require.Equal(t, 1, len(data.Nodes))
	assert.Contains(t, data.Nodes[0].Description, "2")
}

func TestBuildTree_FileDescription_ContainsIssueCount(t *testing.T) {
	builder := NewTreeBuilder()

	filePath := types.FilePath("/project/main.go")
	issue1 := testutil.NewMockIssue("oss-1", filePath)
	issue1.Product = product.ProductOpenSource
	issue2 := testutil.NewMockIssue("oss-2", filePath)
	issue2.Product = product.ProductOpenSource

	supportedTypes := map[product.FilterableIssueType]bool{
		product.FilterableIssueTypeOpenSource: true,
	}
	issues := snyk.IssuesByFile{filePath: {issue1, issue2}}

	data := builder.BuildTreeFromFolderData([]FolderData{
		{
			FolderPath:          "/project",
			FolderName:          "project",
			SupportedIssueTypes: supportedTypes,
			AllIssues:           issues,
			FilteredIssues:      issues,
		},
	})

	productNode := data.Nodes[0]
	fileNode := findChildByType(productNode.Children, NodeTypeFile)
	require.NotNil(t, fileNode)
	assert.Contains(t, fileNode.Description, "2")
}

func TestBuildTree_TotalIssues_ComputedAcrossAllProducts(t *testing.T) {
	builder := NewTreeBuilder()

	filePath := types.FilePath("/project/main.go")
	codeIssue := testutil.NewMockIssue("code-1", filePath)
	codeIssue.Product = product.ProductCode
	codeIssue.AdditionalData = &snyk.CodeIssueData{Key: "k1", Title: "Code Issue"}

	ossIssue := testutil.NewMockIssue("oss-1", filePath)
	ossIssue.Product = product.ProductOpenSource

	supportedTypes := map[product.FilterableIssueType]bool{
		product.FilterableIssueTypeCodeSecurity: true,
		product.FilterableIssueTypeOpenSource:   true,
	}
	issues := snyk.IssuesByFile{filePath: {codeIssue, ossIssue}}

	data := builder.BuildTreeFromFolderData([]FolderData{
		{
			FolderPath:          "/project",
			FolderName:          "project",
			SupportedIssueTypes: supportedTypes,
			AllIssues:           issues,
			FilteredIssues:      issues,
		},
	})

	assert.Equal(t, 2, data.TotalIssues, "TotalIssues should count all issues across products")
}

func TestBuildTree_FileNodes_HaveProductSet(t *testing.T) {
	builder := NewTreeBuilder()

	filePath := types.FilePath("/project/main.go")
	issue := testutil.NewMockIssue("oss-1", filePath)
	issue.Product = product.ProductOpenSource

	supportedTypes := map[product.FilterableIssueType]bool{
		product.FilterableIssueTypeOpenSource: true,
	}
	issues := snyk.IssuesByFile{filePath: {issue}}

	data := builder.BuildTreeFromFolderData([]FolderData{
		{
			FolderPath:          "/project",
			FolderName:          "project",
			SupportedIssueTypes: supportedTypes,
			AllIssues:           issues,
			FilteredIssues:      issues,
		},
	})

	require.Equal(t, 1, len(data.Nodes))
	fileNode := findChildByType(data.Nodes[0].Children, NodeTypeFile)
	require.NotNil(t, fileNode)
	assert.Equal(t, product.ProductOpenSource, fileNode.Product, "file nodes should have product set for lazy-load")
}

func TestBuildTree_IssuesSortedByPriority_NotJustSeverityEnum(t *testing.T) {
	builder := NewTreeBuilder()

	filePath := types.FilePath("/project/main.go")
	// Two high-severity issues with different priority scores
	issueHighLowScore := testutil.NewMockIssueWithSeverity("high-low", filePath, types.High)
	issueHighLowScore.Product = product.ProductCode
	issueHighLowScore.AdditionalData = &snyk.CodeIssueData{Key: "k1", Title: "High Low Score", PriorityScore: 100}

	issueHighHighScore := testutil.NewMockIssueWithSeverity("high-high", filePath, types.High)
	issueHighHighScore.Product = product.ProductCode
	issueHighHighScore.AdditionalData = &snyk.CodeIssueData{Key: "k2", Title: "High High Score", PriorityScore: 900}

	supportedTypes := map[product.FilterableIssueType]bool{
		product.FilterableIssueTypeCodeSecurity: true,
	}
	issues := snyk.IssuesByFile{filePath: {issueHighLowScore, issueHighHighScore}}

	data := builder.BuildTreeFromFolderData([]FolderData{
		{
			FolderPath:          "/project",
			FolderName:          "project",
			SupportedIssueTypes: supportedTypes,
			AllIssues:           issues,
			FilteredIssues:      issues,
		},
	})

	productNode := data.Nodes[0]
	fileNode := findChildByType(productNode.Children, NodeTypeFile)
	require.NotNil(t, fileNode)
	require.Equal(t, 2, len(fileNode.Children))

	// Higher score should come first (sortIssuesByPriority sorts descending)
	assert.Equal(t, "High High Score", fileNode.Children[0].Label)
	assert.Equal(t, "High Low Score", fileNode.Children[1].Label)
}

func TestSortIssuesByPriority_CriticalBeforeHigh(t *testing.T) {
	filePath := types.FilePath("/project/main.go")
	issueCrit := testutil.NewMockIssueWithSeverity("crit-1", filePath, types.Critical)
	issueCrit.AdditionalData = &snyk.CodeIssueData{Key: "k1", Title: "Critical"}

	issueHigh := testutil.NewMockIssueWithSeverity("high-1", filePath, types.High)
	issueHigh.AdditionalData = &snyk.CodeIssueData{Key: "k2", Title: "High"}

	issues := []types.Issue{issueHigh, issueCrit}
	sortIssuesByPriority(issues)

	assert.Equal(t, types.Critical, issues[0].GetSeverity())
	assert.Equal(t, types.High, issues[1].GetSeverity())
}

func TestBuildIssueChunkForFileFromFolderData_ReturnsCorrectSlice(t *testing.T) {
	builder := NewTreeBuilder()

	filePath := types.FilePath("/project/main.go")
	issue1 := testutil.NewMockIssueWithSeverity("crit-1", filePath, types.Critical)
	issue1.Product = product.ProductCode
	issue1.AdditionalData = &snyk.CodeIssueData{Key: "k1", Title: "Critical Issue"}

	issue2 := testutil.NewMockIssueWithSeverity("high-1", filePath, types.High)
	issue2.Product = product.ProductCode
	issue2.AdditionalData = &snyk.CodeIssueData{Key: "k2", Title: "High Issue"}

	issue3 := testutil.NewMockIssueWithSeverity("med-1", filePath, types.Medium)
	issue3.Product = product.ProductCode
	issue3.AdditionalData = &snyk.CodeIssueData{Key: "k3", Title: "Medium Issue"}

	supportedTypes := map[product.FilterableIssueType]bool{
		product.FilterableIssueTypeCodeSecurity: true,
	}
	issues := snyk.IssuesByFile{filePath: {issue1, issue2, issue3}}

	folders := []FolderData{
		{
			FolderPath:          "/project",
			FolderName:          "project",
			SupportedIssueTypes: supportedTypes,
			AllIssues:           issues,
			FilteredIssues:      issues,
		},
	}

	// Request first 2 issues
	nodes, total := builder.BuildIssueChunkForFileFromFolderData(
		folders, filePath, product.ProductCode,
		types.TreeViewRange{Start: 0, End: 2},
	)

	assert.Equal(t, 3, total, "total should reflect all matching issues")
	require.Equal(t, 2, len(nodes), "should return exactly 2 nodes")
	// Sorted by priority: Critical first
	assert.Equal(t, types.Critical, nodes[0].Severity)
	assert.Equal(t, types.High, nodes[1].Severity)
}

func TestBuildIssueChunkForFileFromFolderData_EmptyFolders_ReturnsNil(t *testing.T) {
	builder := NewTreeBuilder()
	nodes, total := builder.BuildIssueChunkForFileFromFolderData(
		nil, "/project/main.go", product.ProductCode,
		types.TreeViewRange{Start: 0, End: 10},
	)
	assert.Nil(t, nodes)
	assert.Equal(t, 0, total)
}

func TestBuildIssueChunkForFileFromFolderData_NoMatchingProduct_ReturnsEmpty(t *testing.T) {
	builder := NewTreeBuilder()

	filePath := types.FilePath("/project/main.go")
	issue := testutil.NewMockIssue("oss-1", filePath)
	issue.Product = product.ProductOpenSource

	folders := []FolderData{
		{
			FolderPath:     "/project",
			FolderName:     "project",
			FilteredIssues: snyk.IssuesByFile{filePath: {issue}},
		},
	}

	nodes, total := builder.BuildIssueChunkForFileFromFolderData(
		folders, filePath, product.ProductCode,
		types.TreeViewRange{Start: 0, End: 10},
	)

	assert.Empty(t, nodes)
	assert.Equal(t, 0, total)
}

func TestBuildIssueChunkForFileFromFolderData_RangeClampedToTotal(t *testing.T) {
	builder := NewTreeBuilder()

	filePath := types.FilePath("/project/main.go")
	issue := testutil.NewMockIssue("oss-1", filePath)
	issue.Product = product.ProductOpenSource

	folders := []FolderData{
		{
			FolderPath:     "/project",
			FolderName:     "project",
			FilteredIssues: snyk.IssuesByFile{filePath: {issue}},
		},
	}

	// Request range larger than total
	nodes, total := builder.BuildIssueChunkForFileFromFolderData(
		folders, filePath, product.ProductOpenSource,
		types.TreeViewRange{Start: 0, End: 999},
	)

	assert.Equal(t, 1, total)
	assert.Equal(t, 1, len(nodes))
}

func TestSortIssuesByPriority_SameSeverity_HigherScoreFirst(t *testing.T) {
	filePath := types.FilePath("/project/main.go")
	issueLow := testutil.NewMockIssueWithSeverity("h-low", filePath, types.High)
	issueLow.AdditionalData = &snyk.CodeIssueData{Key: "k1", Title: "Low Score", PriorityScore: 50}

	issueHighScore := testutil.NewMockIssueWithSeverity("h-high", filePath, types.High)
	issueHighScore.AdditionalData = &snyk.CodeIssueData{Key: "k2", Title: "High Score", PriorityScore: 999}

	issues := []types.Issue{issueLow, issueHighScore}
	sortIssuesByPriority(issues)

	assert.Equal(t, "h-high", issues[0].GetID())
	assert.Equal(t, "h-low", issues[1].GetID())
}

// helper to find a child by type
func findChildByType(nodes []TreeNode, nodeType NodeType) *TreeNode {
	for i := range nodes {
		if nodes[i].Type == nodeType {
			return &nodes[i]
		}
	}
	return nil
}

// helper to filter children by type
func filterChildrenByType(nodes []TreeNode, nodeType NodeType) []TreeNode {
	var result []TreeNode
	for _, n := range nodes {
		if n.Type == nodeType {
			result = append(result, n)
		}
	}
	return result
}
