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
	"strings"
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

func TestTreeHtmlRenderer_ContainsEmbeddedTreeJS(t *testing.T) {
	c := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(c)
	require.NoError(t, err)

	html := renderer.RenderTreeView(TreeViewData{})

	// tree.js defines these constants — verify embedded JS is present
	assert.Contains(t, html, "MAX_AUTO_EXPAND_NODES")
	assert.Contains(t, html, "ISSUE_CHUNK_SIZE")
	assert.Contains(t, html, "__ideTreeRequestIssueChunk__")
	assert.Contains(t, html, "__onIdeTreeIssueChunk__")
}

func TestTreeHtmlRenderer_TreeContainer_HasTotalIssuesAttribute(t *testing.T) {
	c := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(c)
	require.NoError(t, err)

	html := renderer.RenderTreeView(TreeViewData{TotalIssues: 42})

	assert.Contains(t, html, `data-total-issues="42"`)
}

func TestTreeHtmlRenderer_FileNode_HasLazyLoadAttributes(t *testing.T) {
	c := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(c)
	require.NoError(t, err)

	fileNode := NewTreeNode(NodeTypeFile, "main.go",
		WithFilePath("/project/main.go"),
		WithProduct(product.ProductCode),
		WithDescription("3 issue(s)"),
		WithChildren([]TreeNode{
			NewTreeNode(NodeTypeIssue, "SQL Injection",
				WithSeverity(types.High),
			),
		}),
	)
	productNode := NewTreeNode(NodeTypeProduct, "Snyk Code",
		WithChildren([]TreeNode{fileNode}),
	)

	html := renderer.RenderTreeView(TreeViewData{
		Nodes: []TreeNode{productNode},
	})

	assert.Contains(t, html, "tree-node-file")
	assert.Contains(t, html, `data-file-path="/project/main.go"`)
	assert.Contains(t, html, `data-product="Snyk Code"`)
	assert.Contains(t, html, `data-issues-loaded="true"`)
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

func TestTreeHtmlRenderer_IssueBadges_PrependedBeforeLabel(t *testing.T) {
	c := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(c)
	require.NoError(t, err)

	issueNode := NewTreeNode(NodeTypeIssue, "SQL Injection",
		WithIsIgnored(true),
		WithIsFixable(true),
		WithIsNew(true),
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

	// Extract the first issue node element to check badge ordering
	marker := `class="tree-node tree-node-issue"`
	issueStart := strings.Index(html, marker)
	require.Greater(t, issueStart, 0, "issue node element should be present")
	// Find the closing </div> of the issue node (outer div has inner row div + closing)
	issueHtml := html[issueStart:]
	// The issue node inner HTML ends at the second </div> (first closes the row, second closes the node)
	firstClose := strings.Index(issueHtml, `</div>`)
	require.Greater(t, firstClose, 0)
	issueRow := issueHtml[:firstClose]

	ignoredIdx := strings.Index(issueRow, `badge-ignored`)
	fixableIdx := strings.Index(issueRow, `badge-fixable`)
	newIdx := strings.Index(issueRow, `badge-new`)
	labelIdx := strings.Index(issueRow, `tree-label`)

	assert.Greater(t, ignoredIdx, 0, "ignored badge should be present")
	assert.Greater(t, fixableIdx, 0, "fixable badge should be present")
	assert.Greater(t, newIdx, 0, "new badge should be present")
	assert.Greater(t, labelIdx, 0, "label should be present")

	// Order: ignored < fixable < new < label (all badges prepended before the label)
	assert.Less(t, ignoredIdx, labelIdx, "ignored badge should come before label")
	assert.Less(t, fixableIdx, labelIdx, "fixable badge should come before label")
	assert.Less(t, newIdx, labelIdx, "new badge should come before label")
	assert.Less(t, ignoredIdx, fixableIdx, "ignored should come before fixable")
	assert.Less(t, fixableIdx, newIdx, "fixable should come before new")
}

func TestTreeHtmlRenderer_RenderIssueChunk_ReturnsIssueHtmlFragment(t *testing.T) {
	c := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(c)
	require.NoError(t, err)

	nodes := []TreeNode{
		NewTreeNode(NodeTypeIssue, "SQL Injection",
			WithSeverity(types.High),
			WithIssueID("issue-1"),
			WithFilePath("/project/main.go"),
		),
		NewTreeNode(NodeTypeIssue, "XSS",
			WithSeverity(types.Medium),
			WithIssueID("issue-2"),
		),
	}

	html := renderer.RenderIssueChunk(nodes, true)

	assert.Contains(t, html, "SQL Injection")
	assert.Contains(t, html, "XSS")
	assert.Contains(t, html, "tree-node-issue")
	assert.Contains(t, html, "tree-node-load-more", "should contain load more marker when hasMore=true")
}

func TestTreeHtmlRenderer_RenderIssueChunk_NoMore_NoLoadMoreMarker(t *testing.T) {
	c := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(c)
	require.NoError(t, err)

	nodes := []TreeNode{
		NewTreeNode(NodeTypeIssue, "SQL Injection", WithSeverity(types.High)),
	}

	html := renderer.RenderIssueChunk(nodes, false)

	assert.Contains(t, html, "SQL Injection")
	assert.NotContains(t, html, "tree-node-load-more", "should NOT contain load more when hasMore=false")
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

func TestTreeHtmlRenderer_FilterToolbar_SeverityButtons_Rendered(t *testing.T) {
	c := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(c)
	require.NoError(t, err)

	html := renderer.RenderTreeView(TreeViewData{
		FilterState: TreeViewFilterState{
			SeverityFilter:   types.NewSeverityFilter(true, true, false, true),
			IssueViewOptions: types.NewIssueViewOptions(true, false),
		},
	})

	// Severity buttons should be present
	assert.Contains(t, html, `data-filter-type="severity"`)
	assert.Contains(t, html, `data-filter-value="critical"`)
	assert.Contains(t, html, `data-filter-value="high"`)
	assert.Contains(t, html, `data-filter-value="medium"`)
	assert.Contains(t, html, `data-filter-value="low"`)

	// Active state based on filter: critical=true, high=true, medium=false, low=true
	assert.Contains(t, html, `data-filter-value="critical" class="filter-btn filter-btn-icon filter-active"`)
	assert.Contains(t, html, `data-filter-value="high" class="filter-btn filter-btn-icon filter-active"`)
	assert.Contains(t, html, `data-filter-value="medium" class="filter-btn filter-btn-icon"`)
	assert.Contains(t, html, `data-filter-value="low" class="filter-btn filter-btn-icon filter-active"`)

	// Severity label and SVG icons in filter bar
	assert.Contains(t, html, `Severity:`)
	assert.Contains(t, html, `<svg`)
}

func TestTreeHtmlRenderer_FilterToolbar_IssueViewButtons_Rendered(t *testing.T) {
	c := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(c)
	require.NoError(t, err)

	html := renderer.RenderTreeView(TreeViewData{
		FilterState: TreeViewFilterState{
			SeverityFilter:   types.DefaultSeverityFilter(),
			IssueViewOptions: types.NewIssueViewOptions(true, false),
		},
	})

	// Issue view buttons
	assert.Contains(t, html, `data-filter-type="issueView"`)
	assert.Contains(t, html, `data-filter-value="openIssues"`)
	assert.Contains(t, html, `data-filter-value="ignoredIssues"`)

	// Open active, ignored inactive
	assert.Contains(t, html, `data-filter-value="openIssues" class="filter-btn filter-active"`)
	assert.Contains(t, html, `data-filter-value="ignoredIssues" class="filter-btn"`)
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

func TestSeveritySVG_Critical_ContainsExpectedColor(t *testing.T) {
	svg := severitySVG(types.Critical)
	assert.Contains(t, svg, "#AB1A1A", "critical SVG should use red color")
	assert.Contains(t, svg, "<svg")
}

func TestSeveritySVG_High_ContainsExpectedColor(t *testing.T) {
	svg := severitySVG(types.High)
	assert.Contains(t, svg, "#D93600", "high SVG should use orange color")
}

func TestSeveritySVG_Medium_ContainsExpectedColor(t *testing.T) {
	svg := severitySVG(types.Medium)
	assert.Contains(t, svg, "#D68000", "medium SVG should use yellow-orange color")
}

func TestSeveritySVG_Low_ContainsExpectedColor(t *testing.T) {
	svg := severitySVG(types.Low)
	assert.Contains(t, svg, "#8F8FB3", "low SVG should use gray color")
}

func TestProductSVG_SnykCode_ContainsValidSVG(t *testing.T) {
	svg := productSVG(product.ProductCode)
	assert.Contains(t, svg, "<svg")
}

func TestProductSVG_OpenSource_ContainsValidSVG(t *testing.T) {
	svg := productSVG(product.ProductOpenSource)
	assert.Contains(t, svg, "<svg")
}

func TestProductSVG_IaC_ContainsValidSVG(t *testing.T) {
	svg := productSVG(product.ProductInfrastructureAsCode)
	assert.Contains(t, svg, "<svg")
}

func TestCheckmarkSVG_ReturnsGreenCheckmark(t *testing.T) {
	svg := checkmarkSVG()
	assert.Contains(t, svg, "#368746", "checkmark should have green color")
	assert.Contains(t, svg, "<svg")
}
