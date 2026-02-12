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
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestTreeHtmlRenderer_NewRenderer_NoError(t *testing.T) {
	c := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(c)
	require.NoError(t, err)
	assert.NotNil(t, renderer)
}

func TestTreeHtmlRenderer_EmptyTree_ReturnsValidHtml(t *testing.T) {
	c := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(c)
	require.NoError(t, err)

	html := renderer.RenderTreeView(TreeViewData{})

	assert.Contains(t, html, "<!DOCTYPE html>")
	assert.Contains(t, html, "</html>")
	assert.Contains(t, html, "${ideStyle}")
	assert.Contains(t, html, "${ideScript}")
}

func TestTreeHtmlRenderer_ContainsCSS(t *testing.T) {
	c := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(c)
	require.NoError(t, err)

	html := renderer.RenderTreeView(TreeViewData{})

	assert.Contains(t, html, ".tree-container")
}

func TestTreeHtmlRenderer_ContainsIE11CompatMeta(t *testing.T) {
	c := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(c)
	require.NoError(t, err)

	html := renderer.RenderTreeView(TreeViewData{})

	assert.Contains(t, html, `X-UA-Compatible`)
	assert.Contains(t, html, `IE=edge`)
}

func TestTreeHtmlRenderer_ProductNodes_Rendered(t *testing.T) {
	c := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(c)
	require.NoError(t, err)

	issueNode := NewTreeNode(NodeTypeIssue, "SQL Injection",
		WithSeverity(types.High),
		WithIssueID("issue-1"),
		WithFilePath("/project/main.go"),
		WithIssueRange(types.Range{Start: types.Position{Line: 42, Character: 0}}),
	)
	fileNode := NewTreeNode(NodeTypeFile, "main.go",
		WithFilePath("/project/main.go"),
		WithDescription("1 issue(s)"),
		WithChildren([]TreeNode{issueNode}),
	)
	productNode := NewTreeNode(NodeTypeProduct, "Snyk Code",
		WithProduct(product.ProductCode),
		WithDescription("1 issue(s)"),
		WithChildren([]TreeNode{fileNode}),
	)

	data := TreeViewData{
		Nodes: []TreeNode{productNode},
	}

	html := renderer.RenderTreeView(data)

	assert.Contains(t, html, "Snyk Code")
	assert.Contains(t, html, "main.go")
	assert.Contains(t, html, "SQL Injection")
}

func TestTreeHtmlRenderer_IssueNode_HasDataAttributes(t *testing.T) {
	c := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(c)
	require.NoError(t, err)

	issueNode := NewTreeNode(NodeTypeIssue, "XSS",
		WithSeverity(types.Medium),
		WithIssueID("xss-1"),
		WithFilePath("/project/handler.go"),
		WithIssueRange(types.Range{
			Start: types.Position{Line: 10, Character: 5},
			End:   types.Position{Line: 10, Character: 25},
		}),
	)
	fileNode := NewTreeNode(NodeTypeFile, "handler.go",
		WithChildren([]TreeNode{issueNode}),
	)
	productNode := NewTreeNode(NodeTypeProduct, "Snyk Code",
		WithChildren([]TreeNode{fileNode}),
	)

	html := renderer.RenderTreeView(TreeViewData{
		Nodes: []TreeNode{productNode},
	})

	// Issue nodes should have data attributes for click navigation
	assert.Contains(t, html, `data-file-path="/project/handler.go"`)
	assert.Contains(t, html, `data-start-line="10"`)
	assert.Contains(t, html, `data-end-line="10"`)
	assert.Contains(t, html, `data-start-char="5"`)
	assert.Contains(t, html, `data-end-char="25"`)
	assert.Contains(t, html, `data-issue-id="xss-1"`)
}

func TestTreeHtmlRenderer_IgnoredIssue_HasIgnoredBadge(t *testing.T) {
	c := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(c)
	require.NoError(t, err)

	issueNode := NewTreeNode(NodeTypeIssue, "Ignored Issue",
		WithIsIgnored(true),
	)
	fileNode := NewTreeNode(NodeTypeFile, "file.go",
		WithChildren([]TreeNode{issueNode}),
	)
	productNode := NewTreeNode(NodeTypeProduct, "OSS",
		WithChildren([]TreeNode{fileNode}),
	)

	html := renderer.RenderTreeView(TreeViewData{
		Nodes: []TreeNode{productNode},
	})

	assert.Contains(t, html, "ignored")
}

func TestTreeHtmlRenderer_ScanInProgress_ShowsIndicator(t *testing.T) {
	c := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(c)
	require.NoError(t, err)

	html := renderer.RenderTreeView(TreeViewData{
		ScanInProgress: true,
	})

	assert.Contains(t, html, "scanning")
}

func TestTreeHtmlRenderer_MultiRoot_FolderNodes_Rendered(t *testing.T) {
	c := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(c)
	require.NoError(t, err)

	folderNode := NewTreeNode(NodeTypeFolder, "project-a",
		WithChildren([]TreeNode{
			NewTreeNode(NodeTypeProduct, "Snyk Code"),
		}),
	)

	html := renderer.RenderTreeView(TreeViewData{
		Nodes:     []TreeNode{folderNode},
		MultiRoot: true,
	})

	assert.Contains(t, html, "project-a")
}
