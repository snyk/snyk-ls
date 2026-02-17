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
	"fmt"
	"strings"
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
	// All 3 products are emitted; find the Code product node
	require.Equal(t, 3, len(data.Nodes), "should have 3 product roots")
	productNode := findChildByLabel(data.Nodes, string(product.ProductCode))
	require.NotNil(t, productNode, "should have Code product node")
	assert.Equal(t, NodeTypeProduct, productNode.Type)
	assert.Equal(t, product.ProductCode, productNode.Product)

	// Product should have info + file children
	fileNode := findChildByType(productNode.Children, NodeTypeFile)
	require.NotNil(t, fileNode, "should have a file node")
	assert.Contains(t, fileNode.Label, "main.go")

	// File should have issue children
	issueNodes := filterChildrenByType(fileNode.Children, NodeTypeIssue)
	require.Equal(t, 1, len(issueNodes))
	assert.Equal(t, types.High, issueNodes[0].Severity)
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

	productNode := findChildByLabel(data.Nodes, string(product.ProductCode))
	require.NotNil(t, productNode)
	fileNode := findChildByType(productNode.Children, NodeTypeFile)
	require.NotNil(t, fileNode)
	issueChildren := filterChildrenByType(fileNode.Children, NodeTypeIssue)
	require.Equal(t, 3, len(issueChildren))

	// Issues sorted: Critical first, then Medium, Low
	assert.Equal(t, types.Critical, issueChildren[0].Severity)
	assert.Equal(t, types.Medium, issueChildren[1].Severity)
	assert.Equal(t, types.Low, issueChildren[2].Severity)
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

	productNode := findChildByLabel(data.Nodes, string(product.ProductOpenSource))
	require.NotNil(t, productNode)
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

	productNode := findChildByLabel(data.Nodes, string(product.ProductOpenSource))
	require.NotNil(t, productNode)
	fileNode := findChildByType(productNode.Children, NodeTypeFile)
	require.NotNil(t, fileNode)
	issueChildren := filterChildrenByType(fileNode.Children, NodeTypeIssue)
	require.Equal(t, 1, len(issueChildren))
	assert.True(t, issueChildren[0].IsIgnored)
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

	productNode := findChildByLabel(data.Nodes, string(product.ProductOpenSource))
	require.NotNil(t, productNode)
	assert.Contains(t, productNode.Description, "2")
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

	productNode := findChildByLabel(data.Nodes, string(product.ProductOpenSource))
	require.NotNil(t, productNode)
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

	productNode := findChildByLabel(data.Nodes, string(product.ProductOpenSource))
	require.NotNil(t, productNode)
	fileNode := findChildByType(productNode.Children, NodeTypeFile)
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

	productNode := findChildByLabel(data.Nodes, string(product.ProductCode))
	require.NotNil(t, productNode)
	fileNode := findChildByType(productNode.Children, NodeTypeFile)
	require.NotNil(t, fileNode)
	issueChildren := filterChildrenByType(fileNode.Children, NodeTypeIssue)
	require.Equal(t, 2, len(issueChildren))

	// Higher score should come first (sortIssuesByPriority sorts descending)
	// Labels now include [line,col] for Code issues
	assert.Contains(t, issueChildren[0].Label, "High High Score")
	assert.Contains(t, issueChildren[1].Label, "High Low Score")
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

func TestBuildIssueChunkForFileFromFolderData_StartGreaterThanEnd_NoPanic(t *testing.T) {
	builder := NewTreeBuilder()

	filePath := types.FilePath("/project/main.go")
	// Need enough issues so that both start and end stay within total,
	// but start > end triggers an invalid slice.
	var issues []types.Issue
	for i := 0; i < 20; i++ {
		iss := testutil.NewMockIssue(fmt.Sprintf("oss-%d", i), filePath)
		iss.Product = product.ProductOpenSource
		issues = append(issues, iss)
	}

	folders := []FolderData{
		{
			FolderPath:     "/project",
			FolderName:     "project",
			FilteredIssues: snyk.IssuesByFile{filePath: issues},
		},
	}

	// start=10 > end=5, with total=20 — both within bounds but inverted
	assert.NotPanics(t, func() {
		nodes, total := builder.BuildIssueChunkForFileFromFolderData(
			folders, filePath, product.ProductOpenSource,
			types.TreeViewRange{Start: 10, End: 5},
		)
		assert.Equal(t, 20, total)
		assert.Equal(t, 0, len(nodes))
	})
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

// --- Step 4.3: Severity breakdown, info nodes, labels ---

func TestBuildTree_ProductNode_SeverityBreakdownDescription(t *testing.T) {
	builder := NewTreeBuilder()
	filePath := types.FilePath("/project/main.go")

	issueHigh := testutil.NewMockIssueWithSeverity("h-1", filePath, types.High)
	issueHigh.Product = product.ProductOpenSource
	issueHigh.AdditionalData = snyk.OssIssueData{Key: "k1", Title: "Vuln A"}

	issueMed1 := testutil.NewMockIssueWithSeverity("m-1", filePath, types.Medium)
	issueMed1.Product = product.ProductOpenSource
	issueMed1.AdditionalData = snyk.OssIssueData{Key: "k2", Title: "Vuln B"}

	issueMed2 := testutil.NewMockIssueWithSeverity("m-2", filePath, types.Medium)
	issueMed2.Product = product.ProductOpenSource
	issueMed2.AdditionalData = snyk.OssIssueData{Key: "k3", Title: "Vuln C"}

	issues := snyk.IssuesByFile{filePath: {issueHigh, issueMed1, issueMed2}}

	data := builder.BuildTreeFromFolderData([]FolderData{{
		FolderPath: "/project", FolderName: "project",
		SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeOpenSource: true},
		AllIssues:           issues, FilteredIssues: issues,
	}})

	require.GreaterOrEqual(t, len(data.Nodes), 1)
	ossNode := findChildByLabel(data.Nodes, string(product.ProductOpenSource))
	require.NotNil(t, ossNode, "should have OSS product node")
	assert.NotContains(t, ossNode.Description, "critical", "0-count severities should be omitted")
	assert.Contains(t, ossNode.Description, "1 high")
	assert.Contains(t, ossNode.Description, "2 medium")
	assert.NotContains(t, ossNode.Description, "low", "0-count severities should be omitted")
	assert.NotNil(t, ossNode.SeverityCounts)
	assert.Equal(t, 0, ossNode.SeverityCounts.Critical)
	assert.Equal(t, 1, ossNode.SeverityCounts.High)
	assert.Equal(t, 2, ossNode.SeverityCounts.Medium)
	assert.Equal(t, 0, ossNode.SeverityCounts.Low)
}

func TestBuildTree_ProductNode_IssueCountInfoChild(t *testing.T) {
	builder := NewTreeBuilder()
	filePath := types.FilePath("/project/main.go")

	issue1 := testutil.NewMockIssueWithSeverity("h-1", filePath, types.High)
	issue1.Product = product.ProductOpenSource
	issue1.AdditionalData = snyk.OssIssueData{Key: "k1", Title: "Vuln"}

	issue2 := testutil.NewMockIssueWithSeverity("m-1", filePath, types.Medium)
	issue2.Product = product.ProductOpenSource
	issue2.AdditionalData = snyk.OssIssueData{Key: "k2", Title: "Vuln2"}

	issues := snyk.IssuesByFile{filePath: {issue1, issue2}}

	data := builder.BuildTreeFromFolderData([]FolderData{{
		FolderPath: "/project", FolderName: "project",
		SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeOpenSource: true},
		AllIssues:           issues, FilteredIssues: issues,
	}})

	ossNode := findChildByLabel(data.Nodes, string(product.ProductOpenSource))
	require.NotNil(t, ossNode)

	infoNodes := filterChildrenByType(ossNode.Children, NodeTypeInfo)
	require.GreaterOrEqual(t, len(infoNodes), 1, "should have at least 1 info node")
	assert.Contains(t, infoNodes[0].Label, "2 issues", "first info node should show issue count")
}

func TestBuildTree_ProductNode_FixableInfoChild(t *testing.T) {
	builder := NewTreeBuilder()
	filePath := types.FilePath("/project/main.go")

	issue := testutil.NewMockIssueWithSeverity("h-1", filePath, types.High)
	issue.Product = product.ProductOpenSource
	issue.AdditionalData = snyk.OssIssueData{
		Key: "k1", Title: "Vuln", IsUpgradable: true, IsPatchable: true,
		UpgradePath: []any{"", "pkg@2.0.0"}, From: []string{"", "pkg@1.0.0"},
	}

	issues := snyk.IssuesByFile{filePath: {issue}}

	data := builder.BuildTreeFromFolderData([]FolderData{{
		FolderPath: "/project", FolderName: "project",
		SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeOpenSource: true},
		AllIssues:           issues, FilteredIssues: issues,
	}})

	ossNode := findChildByLabel(data.Nodes, string(product.ProductOpenSource))
	require.NotNil(t, ossNode)

	infoNodes := filterChildrenByType(ossNode.Children, NodeTypeInfo)
	fixableNode := findInfoNodeContaining(infoNodes, "fixable")
	require.NotNil(t, fixableNode, "should have fixable info node")
	assert.Contains(t, fixableNode.Label, "1")
	assert.Contains(t, fixableNode.Label, "fixable")
}

func TestBuildTree_ProductNode_ZeroFixable_ShowsNoFixableMessage(t *testing.T) {
	builder := NewTreeBuilder()
	filePath := types.FilePath("/project/main.go")

	issue := testutil.NewMockIssueWithSeverity("h-1", filePath, types.High)
	issue.Product = product.ProductOpenSource
	issue.AdditionalData = snyk.OssIssueData{Key: "k1", Title: "Vuln"}

	issues := snyk.IssuesByFile{filePath: {issue}}

	data := builder.BuildTreeFromFolderData([]FolderData{{
		FolderPath: "/project", FolderName: "project",
		SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeOpenSource: true},
		AllIssues:           issues, FilteredIssues: issues,
	}})

	ossNode := findChildByLabel(data.Nodes, string(product.ProductOpenSource))
	require.NotNil(t, ossNode)

	infoNodes := filterChildrenByType(ossNode.Children, NodeTypeInfo)
	noFixableNode := findInfoNodeContaining(infoNodes, "no issues automatically fixable")
	require.NotNil(t, noFixableNode, "should have 'no fixable' info node")
}

func TestBuildTree_EmptyProduct_ShowsCongratsInfoChild(t *testing.T) {
	builder := NewTreeBuilder()

	data := builder.BuildTreeFromFolderData([]FolderData{{
		FolderPath: "/project", FolderName: "project",
		SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeOpenSource: true},
		AllIssues:           snyk.IssuesByFile{},
		FilteredIssues:      snyk.IssuesByFile{},
	}})

	ossNode := findChildByLabel(data.Nodes, string(product.ProductOpenSource))
	require.NotNil(t, ossNode, "empty product should still appear")

	infoNodes := filterChildrenByType(ossNode.Children, NodeTypeInfo)
	congratsNode := findInfoNodeContaining(infoNodes, "No issues found")
	require.NotNil(t, congratsNode, "empty product should show congrats info child")
}

func TestBuildTree_OssIssueLabel_PackageAtVersionTitle(t *testing.T) {
	builder := NewTreeBuilder()
	filePath := types.FilePath("/project/package.json")

	issue := testutil.NewMockIssueWithSeverity("oss-1", filePath, types.High)
	issue.Product = product.ProductOpenSource
	issue.Range = types.Range{
		Start: types.Position{Line: 10, Character: 5},
		End:   types.Position{Line: 10, Character: 20},
	}
	issue.AdditionalData = snyk.OssIssueData{
		Key: "k1", Title: "Prototype Pollution", PackageName: "lodash", Version: "4.17.20",
	}

	issues := snyk.IssuesByFile{filePath: {issue}}

	data := builder.BuildTreeFromFolderData([]FolderData{{
		FolderPath: "/project", FolderName: "project",
		SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeOpenSource: true},
		AllIssues:           issues, FilteredIssues: issues,
	}})

	ossNode := findChildByLabel(data.Nodes, string(product.ProductOpenSource))
	require.NotNil(t, ossNode)
	fileNodes := filterChildrenByType(ossNode.Children, NodeTypeFile)
	require.GreaterOrEqual(t, len(fileNodes), 1)
	issueNodes := filterChildrenByType(fileNodes[0].Children, NodeTypeIssue)
	require.Equal(t, 1, len(issueNodes))
	assert.Equal(t, "lodash@4.17.20: Prototype Pollution [11,5]", issueNodes[0].Label)
}

func TestBuildTree_CodeIssueLabel_TitleWithLineCol(t *testing.T) {
	builder := NewTreeBuilder()
	filePath := types.FilePath("/project/main.go")

	issue := testutil.NewMockIssueWithSeverity("code-1", filePath, types.High)
	issue.Product = product.ProductCode
	issue.Range = types.Range{
		Start: types.Position{Line: 41, Character: 9},
		End:   types.Position{Line: 41, Character: 30},
	}
	issue.AdditionalData = &snyk.CodeIssueData{Key: "k1", Title: "SQL Injection"}

	issues := snyk.IssuesByFile{filePath: {issue}}

	data := builder.BuildTreeFromFolderData([]FolderData{{
		FolderPath: "/project", FolderName: "project",
		SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeCodeSecurity: true},
		AllIssues:           issues, FilteredIssues: issues,
	}})

	codeNode := findChildByLabel(data.Nodes, string(product.ProductCode))
	require.NotNil(t, codeNode)
	fileNodes := filterChildrenByType(codeNode.Children, NodeTypeFile)
	require.GreaterOrEqual(t, len(fileNodes), 1)
	issueNodes := filterChildrenByType(fileNodes[0].Children, NodeTypeIssue)
	require.Equal(t, 1, len(issueNodes))
	assert.Equal(t, "SQL Injection [42,9]", issueNodes[0].Label)
}

func TestBuildTree_OssFileDescription_SaysVulnerabilities(t *testing.T) {
	builder := NewTreeBuilder()
	filePath := types.FilePath("/project/package.json")

	issue := testutil.NewMockIssueWithSeverity("oss-1", filePath, types.High)
	issue.Product = product.ProductOpenSource
	issue.AdditionalData = snyk.OssIssueData{Key: "k1", Title: "Vuln"}

	issues := snyk.IssuesByFile{filePath: {issue}}

	data := builder.BuildTreeFromFolderData([]FolderData{{
		FolderPath: "/project", FolderName: "project",
		SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeOpenSource: true},
		AllIssues:           issues, FilteredIssues: issues,
	}})

	ossNode := findChildByLabel(data.Nodes, string(product.ProductOpenSource))
	require.NotNil(t, ossNode)
	fileNodes := filterChildrenByType(ossNode.Children, NodeTypeFile)
	require.GreaterOrEqual(t, len(fileNodes), 1)
	assert.Contains(t, fileNodes[0].Description, "vulnerabilit")
}

func TestBuildTree_CodeFileDescription_SaysIssues(t *testing.T) {
	builder := NewTreeBuilder()
	filePath := types.FilePath("/project/main.go")

	issue := testutil.NewMockIssueWithSeverity("code-1", filePath, types.High)
	issue.Product = product.ProductCode
	issue.AdditionalData = &snyk.CodeIssueData{Key: "k1", Title: "Hardcoded Secret"}

	issues := snyk.IssuesByFile{filePath: {issue}}

	data := builder.BuildTreeFromFolderData([]FolderData{{
		FolderPath: "/project", FolderName: "project",
		SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeCodeSecurity: true},
		AllIssues:           issues, FilteredIssues: issues,
	}})

	codeNode := findChildByLabel(data.Nodes, string(product.ProductCode))
	require.NotNil(t, codeNode)
	fileNodes := filterChildrenByType(codeNode.Children, NodeTypeFile)
	require.GreaterOrEqual(t, len(fileNodes), 1)
	assert.Contains(t, fileNodes[0].Description, "issue")
	assert.NotContains(t, fileNodes[0].Description, "vulnerabilit")
}

func TestBuildTree_ExpandState_DefaultsApplied(t *testing.T) {
	builder := NewTreeBuilder()

	filePath := types.FilePath("/project/main.go")
	// Create more than maxAutoExpandIssues so file nodes stay collapsed by default.
	var issueList []types.Issue
	for i := 0; i < maxAutoExpandIssues+1; i++ {
		issue := testutil.NewMockIssueWithSeverity(fmt.Sprintf("code-%d", i), filePath, types.High)
		issue.Product = product.ProductCode
		issue.AdditionalData = &snyk.CodeIssueData{Key: fmt.Sprintf("k%d", i), Title: fmt.Sprintf("Issue %d", i)}
		issueList = append(issueList, issue)
	}

	data := builder.BuildTreeFromFolderData([]FolderData{{
		FolderPath: "/project", FolderName: "project",
		SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeCodeSecurity: true},
		AllIssues:           snyk.IssuesByFile{filePath: issueList},
		FilteredIssues:      snyk.IssuesByFile{filePath: issueList},
	}})

	// Product nodes should be expanded by default
	codeNode := findChildByLabel(data.Nodes, string(product.ProductCode))
	require.NotNil(t, codeNode)
	assert.True(t, codeNode.Expanded, "product nodes should be expanded by default")

	// File nodes should be collapsed by default for large trees
	fileNode := findChildByType(codeNode.Children, NodeTypeFile)
	require.NotNil(t, fileNode)
	assert.False(t, fileNode.Expanded, "file nodes should be collapsed by default for large trees")
}

func TestBuildTree_ExpandState_OverridesApplied(t *testing.T) {
	es := NewExpandState()
	builder := NewTreeBuilder(es)

	filePath := types.FilePath("/project/main.go")
	issue := testutil.NewMockIssue("issue-1", filePath)
	issue.Product = product.ProductCode
	issue.Severity = types.High
	issue.AdditionalData = &snyk.CodeIssueData{Key: "key-1", Title: "SQL Injection"}

	// Override: collapse the product node, expand the file node
	es.Set("product:/project:Snyk Code", false)
	es.Set("file:Snyk Code:/project/main.go", true)

	data := builder.BuildTreeFromFolderData([]FolderData{{
		FolderPath: "/project", FolderName: "project",
		SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeCodeSecurity: true},
		AllIssues:           snyk.IssuesByFile{filePath: {issue}},
		FilteredIssues:      snyk.IssuesByFile{filePath: {issue}},
	}})

	codeNode := findChildByLabel(data.Nodes, string(product.ProductCode))
	require.NotNil(t, codeNode)
	assert.False(t, codeNode.Expanded, "product should be collapsed per override")

	fileNode := findChildByType(codeNode.Children, NodeTypeFile)
	require.NotNil(t, fileNode)
	assert.True(t, fileNode.Expanded, "file should be expanded per override")
}

func TestBuildTree_NodeIDs_AreDeterministic(t *testing.T) {
	builder := NewTreeBuilder()

	filePath := types.FilePath("/project/main.go")
	issue := testutil.NewMockIssue("issue-1", filePath)
	issue.Product = product.ProductCode
	issue.Severity = types.High
	issue.AdditionalData = &snyk.CodeIssueData{Key: "key-1", Title: "SQL Injection"}

	folderData := []FolderData{{
		FolderPath: "/project", FolderName: "project",
		SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeCodeSecurity: true},
		AllIssues:           snyk.IssuesByFile{filePath: {issue}},
		FilteredIssues:      snyk.IssuesByFile{filePath: {issue}},
	}}

	data1 := builder.BuildTreeFromFolderData(folderData)
	data2 := builder.BuildTreeFromFolderData(folderData)

	ids1 := collectAllIDs(data1.Nodes)
	ids2 := collectAllIDs(data2.Nodes)

	require.Equal(t, len(ids1), len(ids2), "both builds should produce the same number of nodes")
	assert.Equal(t, ids1, ids2, "node IDs should be identical across rebuilds")
	for _, id := range ids1 {
		assert.NotEmpty(t, id, "no node should have an empty ID")
	}
}

func TestBuildTree_NodeIDs_MultiRoot_AreDeterministic(t *testing.T) {
	builder := NewTreeBuilder()

	filePath1 := types.FilePath("/project-a/main.go")
	issue1 := testutil.NewMockIssue("issue-1", filePath1)
	issue1.Product = product.ProductOpenSource

	filePath2 := types.FilePath("/project-b/app.go")
	issue2 := testutil.NewMockIssue("issue-2", filePath2)
	issue2.Product = product.ProductOpenSource

	folderData := []FolderData{
		{
			FolderPath: "/project-a", FolderName: "project-a",
			SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeOpenSource: true},
			AllIssues:           snyk.IssuesByFile{filePath1: {issue1}},
			FilteredIssues:      snyk.IssuesByFile{filePath1: {issue1}},
		},
		{
			FolderPath: "/project-b", FolderName: "project-b",
			SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeOpenSource: true},
			AllIssues:           snyk.IssuesByFile{filePath2: {issue2}},
			FilteredIssues:      snyk.IssuesByFile{filePath2: {issue2}},
		},
	}

	data1 := builder.BuildTreeFromFolderData(folderData)
	data2 := builder.BuildTreeFromFolderData(folderData)

	ids1 := collectAllIDs(data1.Nodes)
	ids2 := collectAllIDs(data2.Nodes)

	assert.Equal(t, ids1, ids2, "multi-root node IDs should be identical across rebuilds")
}

// collectAllIDs traverses the tree and returns all node IDs in order.
func collectAllIDs(nodes []TreeNode) []string {
	var ids []string
	for _, n := range nodes {
		ids = append(ids, n.ID)
		ids = append(ids, collectAllIDs(n.Children)...)
	}
	return ids
}

// helper to find a child by label
func findChildByLabel(nodes []TreeNode, label string) *TreeNode {
	for i := range nodes {
		if nodes[i].Label == label {
			return &nodes[i]
		}
	}
	return nil
}

// helper to find an info node containing a substring
func findInfoNodeContaining(nodes []TreeNode, substr string) *TreeNode {
	for i := range nodes {
		if nodes[i].Type == NodeTypeInfo && containsIgnoreCase(nodes[i].Label, substr) {
			return &nodes[i]
		}
	}
	return nil
}

func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) &&
		(strings.Contains(strings.ToLower(s), strings.ToLower(substr)))
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

func TestBuildTree_ProductDescription_OmitsZeroSeverityCounts(t *testing.T) {
	builder := NewTreeBuilder()
	filePath := types.FilePath("/project/main.go")

	issue := testutil.NewMockIssueWithSeverity("code-1", filePath, types.High)
	issue.Product = product.ProductCode
	issue.AdditionalData = &snyk.CodeIssueData{Key: "k1", Title: "XSS"}

	issues := snyk.IssuesByFile{filePath: {issue}}

	data := builder.BuildTreeFromFolderData([]FolderData{{
		FolderPath: "/project", FolderName: "project",
		SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeCodeSecurity: true},
		AllIssues:           issues, FilteredIssues: issues,
	}})

	codeNode := findChildByLabel(data.Nodes, string(product.ProductCode))
	require.NotNil(t, codeNode)
	assert.NotContains(t, codeNode.Description, "0 critical", "should not show 0-count severities")
	assert.NotContains(t, codeNode.Description, "0 medium", "should not show 0-count severities")
	assert.NotContains(t, codeNode.Description, "0 low", "should not show 0-count severities")
	assert.Contains(t, codeNode.Description, "1 high", "should show non-zero severity count")
}

func TestBuildTree_SmallTree_FileNodesAutoExpanded(t *testing.T) {
	builder := NewTreeBuilder()
	filePath := types.FilePath("/project/main.go")

	issue := testutil.NewMockIssueWithSeverity("code-1", filePath, types.High)
	issue.Product = product.ProductCode
	issue.AdditionalData = &snyk.CodeIssueData{Key: "k1", Title: "XSS"}

	issues := snyk.IssuesByFile{filePath: {issue}}

	data := builder.BuildTreeFromFolderData([]FolderData{{
		FolderPath: "/project", FolderName: "project",
		SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeCodeSecurity: true},
		AllIssues:           issues, FilteredIssues: issues,
	}})

	// With only 1 issue (below threshold), file nodes should auto-expand
	codeNode := findChildByLabel(data.Nodes, string(product.ProductCode))
	require.NotNil(t, codeNode)
	fileNode := findChildByType(codeNode.Children, NodeTypeFile)
	require.NotNil(t, fileNode)
	assert.True(t, fileNode.Expanded, "file nodes should auto-expand when total issues <= threshold")
}

func TestBuildTree_SmallTree_UserCollapse_Preserved(t *testing.T) {
	es := NewExpandState()
	builder := NewTreeBuilder(es)
	filePath := types.FilePath("/project/main.go")

	issue := testutil.NewMockIssueWithSeverity("code-1", filePath, types.High)
	issue.Product = product.ProductCode
	issue.AdditionalData = &snyk.CodeIssueData{Key: "k1", Title: "XSS"}

	issues := snyk.IssuesByFile{filePath: {issue}}

	// User explicitly collapsed this file node
	es.Set("file:Snyk Code:/project/main.go", false)

	data := builder.BuildTreeFromFolderData([]FolderData{{
		FolderPath: "/project", FolderName: "project",
		SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeCodeSecurity: true},
		AllIssues:           issues, FilteredIssues: issues,
	}})

	// Even though total issues is small, user override should win
	codeNode := findChildByLabel(data.Nodes, string(product.ProductCode))
	require.NotNil(t, codeNode)
	fileNode := findChildByType(codeNode.Children, NodeTypeFile)
	require.NotNil(t, fileNode)
	assert.False(t, fileNode.Expanded, "user collapse override must be preserved even for small trees")
}

func TestBuildTree_ThresholdCrossing_PreservesAutoExpandedState(t *testing.T) {
	es := NewExpandState()

	// First render: small tree (1 issue, below threshold) → file node auto-expands
	filePath := types.FilePath("/project/main.go")
	issue := testutil.NewMockIssueWithSeverity("code-1", filePath, types.High)
	issue.Product = product.ProductCode
	issue.AdditionalData = &snyk.CodeIssueData{Key: "k1", Title: "XSS"}

	smallIssues := snyk.IssuesByFile{filePath: {issue}}

	builder1 := NewTreeBuilder(es)
	data1 := builder1.BuildTreeFromFolderData([]FolderData{{
		FolderPath: "/project", FolderName: "project",
		SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeCodeSecurity: true},
		AllIssues:           smallIssues, FilteredIssues: smallIssues,
	}})

	codeNode1 := findChildByLabel(data1.Nodes, string(product.ProductCode))
	require.NotNil(t, codeNode1)
	fileNode1 := findChildByType(codeNode1.Children, NodeTypeFile)
	require.NotNil(t, fileNode1)
	assert.True(t, fileNode1.Expanded, "first render: file node should be auto-expanded for small tree")

	// Second render: add many issues crossing the threshold (> maxAutoExpandIssues)
	var bigIssues []types.Issue
	for i := 0; i < maxAutoExpandIssues+10; i++ {
		mi := testutil.NewMockIssueWithSeverity(fmt.Sprintf("code-%d", i), filePath, types.Medium)
		mi.Product = product.ProductCode
		mi.AdditionalData = &snyk.CodeIssueData{Key: fmt.Sprintf("k%d", i), Title: fmt.Sprintf("Issue %d", i)}
		bigIssues = append(bigIssues, mi)
	}
	bigIssuesByFile := snyk.IssuesByFile{filePath: bigIssues}

	builder2 := NewTreeBuilder(es)
	data2 := builder2.BuildTreeFromFolderData([]FolderData{{
		FolderPath: "/project", FolderName: "project",
		SupportedIssueTypes: map[product.FilterableIssueType]bool{product.FilterableIssueTypeCodeSecurity: true},
		AllIssues:           bigIssuesByFile, FilteredIssues: bigIssuesByFile,
	}})

	codeNode2 := findChildByLabel(data2.Nodes, string(product.ProductCode))
	require.NotNil(t, codeNode2)
	fileNode2 := findChildByType(codeNode2.Children, NodeTypeFile)
	require.NotNil(t, fileNode2)
	assert.True(t, fileNode2.Expanded, "second render: file node must stay expanded after threshold crossing")
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
