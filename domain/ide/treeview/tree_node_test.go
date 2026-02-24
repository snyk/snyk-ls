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

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestNewTreeNode_IssueNode(t *testing.T) {
	node := NewTreeNode(
		NodeTypeIssue,
		"SQL Injection",
		WithID("issue:issue-123"),
		WithDescription("src/main.go [42, 10]"),
		WithSeverity(types.High),
		WithProduct(product.ProductCode),
		WithFilePath("/project/src/main.go"),
		WithIssueRange(types.Range{
			Start: types.Position{Line: 42, Character: 10},
			End:   types.Position{Line: 42, Character: 30},
		}),
		WithIssueID("issue-123"),
		WithIsIgnored(false),
		WithIsNew(true),
		WithIsFixable(true),
	)

	assert.Equal(t, "issue:issue-123", node.ID, "node ID should match the WithID value")
	assert.Equal(t, NodeTypeIssue, node.Type)
	assert.Equal(t, "SQL Injection", node.Label)
	assert.Equal(t, "src/main.go [42, 10]", node.Description)
	assert.Equal(t, types.High, node.Severity)
	assert.Equal(t, product.ProductCode, node.Product)
	assert.Equal(t, types.FilePath("/project/src/main.go"), node.FilePath)
	assert.Equal(t, 42, node.IssueRange.Start.Line)
	assert.Equal(t, "issue-123", node.IssueID)
	assert.False(t, node.IsIgnored)
	assert.True(t, node.IsNew)
	assert.True(t, node.IsFixable)
	assert.Empty(t, node.Children)
}

func TestNewTreeNode_FileNode_WithChildren(t *testing.T) {
	issueNode := NewTreeNode(NodeTypeIssue, "XSS Vulnerability",
		WithSeverity(types.Medium),
		WithIssueID("issue-456"),
	)

	fileNode := NewTreeNode(NodeTypeFile, "src/handler.go",
		WithDescription("1 issue"),
		WithFilePath("/project/src/handler.go"),
		WithChildren([]TreeNode{issueNode}),
	)

	assert.Equal(t, NodeTypeFile, fileNode.Type)
	assert.Equal(t, "src/handler.go", fileNode.Label)
	assert.Equal(t, 1, len(fileNode.Children))
	assert.Equal(t, "XSS Vulnerability", fileNode.Children[0].Label)
}

func TestNewTreeNode_ProductNode(t *testing.T) {
	node := NewTreeNode(NodeTypeProduct, "Snyk Code",
		WithProduct(product.ProductCode),
		WithDescription("5 issues"),
	)

	assert.Equal(t, NodeTypeProduct, node.Type)
	assert.Equal(t, "Snyk Code", node.Label)
	assert.Equal(t, product.ProductCode, node.Product)
	assert.Equal(t, "5 issues", node.Description)
}

func TestNewTreeNode_FolderNode(t *testing.T) {
	node := NewTreeNode(NodeTypeFolder, "/project-a",
		WithFilePath("/workspace/project-a"),
	)

	assert.Equal(t, NodeTypeFolder, node.Type)
	assert.Equal(t, "/project-a", node.Label)
}

func TestNewTreeNode_InfoNode(t *testing.T) {
	node := NewTreeNode(NodeTypeInfo, "✋ 5 issues found")

	assert.Equal(t, NodeTypeInfo, node.Type)
	assert.Equal(t, "✋ 5 issues found", node.Label)
	assert.Empty(t, node.Children)
}

func TestTreeNode_WithID_SetsExplicitID(t *testing.T) {
	node1 := NewTreeNode(NodeTypeIssue, "Issue 1", WithID("issue:abc"))
	node2 := NewTreeNode(NodeTypeIssue, "Issue 2", WithID("issue:def"))

	assert.Equal(t, "issue:abc", node1.ID)
	assert.Equal(t, "issue:def", node2.ID)
	assert.NotEqual(t, node1.ID, node2.ID, "different WithID values should produce different IDs")
}

func TestTreeNode_NoWithID_EmptyID(t *testing.T) {
	node := NewTreeNode(NodeTypeIssue, "Issue 1")
	assert.Empty(t, node.ID, "without WithID the ID should be empty")
}

func TestNodeType_String(t *testing.T) {
	assert.Equal(t, "folder", string(NodeTypeFolder))
	assert.Equal(t, "product", string(NodeTypeProduct))
	assert.Equal(t, "file", string(NodeTypeFile))
	assert.Equal(t, "issue", string(NodeTypeIssue))
	assert.Equal(t, "info", string(NodeTypeInfo))
}

func TestTreeViewFilterState_Default(t *testing.T) {
	filterState := DefaultTreeViewFilterState()

	assert.True(t, filterState.SeverityFilter.Critical)
	assert.True(t, filterState.SeverityFilter.High)
	assert.True(t, filterState.SeverityFilter.Medium)
	assert.True(t, filterState.SeverityFilter.Low)
	assert.True(t, filterState.IssueViewOptions.OpenIssues)
	assert.True(t, filterState.IssueViewOptions.IgnoredIssues)
}

func TestSeverityCounts_Struct(t *testing.T) {
	counts := SeverityCounts{
		Critical: 1,
		High:     2,
		Medium:   3,
		Low:      4,
	}
	assert.Equal(t, 1, counts.Critical)
	assert.Equal(t, 2, counts.High)
	assert.Equal(t, 3, counts.Medium)
	assert.Equal(t, 4, counts.Low)
}

func TestWithSeverityCounts_SetsField(t *testing.T) {
	counts := &SeverityCounts{Critical: 1, High: 2, Medium: 3, Low: 4}
	node := NewTreeNode(NodeTypeProduct, "Open Source", WithSeverityCounts(counts))
	assert.Equal(t, counts, node.SeverityCounts)
}

func TestWithFixableCount_SetsField(t *testing.T) {
	node := NewTreeNode(NodeTypeProduct, "Open Source", WithFixableCount(5))
	assert.Equal(t, 5, node.FixableCount)
}

func TestWithIssueCount_SetsField(t *testing.T) {
	node := NewTreeNode(NodeTypeProduct, "Open Source", WithIssueCount(10))
	assert.Equal(t, 10, node.IssueCount)
}

func TestWithEnabled_SetsField(t *testing.T) {
	enabled := true
	node := NewTreeNode(NodeTypeProduct, "Open Source", WithEnabled(&enabled))
	assert.NotNil(t, node.Enabled)
	assert.True(t, *node.Enabled)

	disabled := false
	node2 := NewTreeNode(NodeTypeProduct, "Open Source", WithEnabled(&disabled))
	assert.NotNil(t, node2.Enabled)
	assert.False(t, *node2.Enabled)
}

func TestWithEnabled_NilMeansEnabled(t *testing.T) {
	node := NewTreeNode(NodeTypeProduct, "Open Source")
	assert.Nil(t, node.Enabled, "nil Enabled should mean product is enabled by default")
}

func TestWithFileIconHTML_SetsField(t *testing.T) {
	node := NewTreeNode(NodeTypeFile, "package.json", WithFileIconHTML(`<svg>npm</svg>`))
	assert.Equal(t, `<svg>npm</svg>`, node.FileIconHTML)
}

func TestWithFileIconHTML_DefaultEmpty(t *testing.T) {
	node := NewTreeNode(NodeTypeFile, "main.go")
	assert.Empty(t, node.FileIconHTML)
}

func TestTreeViewData_Construction(t *testing.T) {
	issueNode := NewTreeNode(NodeTypeIssue, "SQL Injection",
		WithSeverity(types.Critical),
	)
	fileNode := NewTreeNode(NodeTypeFile, "main.go",
		WithChildren([]TreeNode{issueNode}),
	)
	productNode := NewTreeNode(NodeTypeProduct, "Snyk Code",
		WithChildren([]TreeNode{fileNode}),
	)

	filterState := DefaultTreeViewFilterState()
	data := TreeViewData{
		Nodes:       []TreeNode{productNode},
		FilterState: filterState,
		MultiRoot:   false,
	}

	assert.Equal(t, 1, len(data.Nodes))
	assert.Equal(t, NodeTypeProduct, data.Nodes[0].Type)
	assert.Equal(t, 1, len(data.Nodes[0].Children))
	assert.Equal(t, 1, len(data.Nodes[0].Children[0].Children))
	assert.False(t, data.MultiRoot)
	assert.True(t, data.FilterState.SeverityFilter.Critical)
	assert.True(t, data.FilterState.IssueViewOptions.OpenIssues)
}
