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
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)
	assert.NotNil(t, renderer)
}

func TestTreeHtmlRenderer_EmptyTree_ReturnsValidHtml(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	html := renderer.RenderTreeView(TreeViewData{})

	assert.Contains(t, html, "<!DOCTYPE html>")
	assert.Contains(t, html, "</html>")
	assert.Contains(t, html, "${ideStyle}")
	assert.Contains(t, html, "${ideScript}")
}

func TestTreeHtmlRenderer_ContainsCSS(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	html := renderer.RenderTreeView(TreeViewData{})

	assert.Contains(t, html, ".tree-container")
}

func TestTreeHtmlRenderer_ContainsEmbeddedTreeJS(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	html := renderer.RenderTreeView(TreeViewData{})

	assert.Contains(t, html, "__ideExecuteCommand__")
}

func TestTreeHtmlRenderer_TreeContainer_HasTotalIssuesAttribute(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	html := renderer.RenderTreeView(TreeViewData{TotalIssues: 42})

	assert.Contains(t, html, `data-total-issues="42"`)
}

func TestTreeHtmlRenderer_FileNode_HasDataAttributes(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
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
	assert.Contains(t, html, `data-product="code"`)
}

func TestTreeHtmlRenderer_UntrustedFolderBanner_HasPerFolderTrustButtons(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	banner := NewTreeNode(NodeTypeInfo, untrustedFolderRationale,
		WithID("info:untrusted-folder"),
		WithInfoVariant("untrusted-folder"),
		WithFolderPaths([]string{"/repo/a", "/repo/b"}),
	)

	html := renderer.RenderTreeView(TreeViewData{Nodes: []TreeNode{banner}})

	assert.Contains(t, html, "tree-node-info--untrusted-folder")
	assert.Contains(t, html, "You should only scan folders you trust")
	// One Trust button per folder, each carrying its own folder path so the JS
	// handler can scope snyk.trustWorkspaceFolders to that folder.
	assert.Contains(t, html, `data-action="trust-folder" data-folder-path="/repo/a"`)
	assert.Contains(t, html, `data-action="trust-folder" data-folder-path="/repo/b"`)
	assert.Equal(t, 2, strings.Count(html, `data-action="trust-folder"`), "expected one Trust button per untrusted folder")
}

func TestTreeHtmlRenderer_UntrustedFolderNode_DimmedAndNoChevron(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	node := NewTreeNode(NodeTypeFolder, "my-project",
		WithID("folder:/repo/my-project"),
		WithFilePath("/repo/my-project"),
		WithUntrusted(true),
	)

	html := renderer.RenderTreeView(TreeViewData{Nodes: []TreeNode{node}})

	// (a) The node element must carry tree-node-untrusted: this drives opacity:0.5
	//     dimming in CSS and signals the user that the folder is not yet trusted.
	assert.Contains(t, html, `class="tree-node tree-node-untrusted"`,
		"untrusted folder must carry tree-node-untrusted class for dimming")

	// (b) The node element must NOT carry tree-node-has-children in any class
	//     attribute value. tree-node-has-children drives chevron visibility and
	//     row expand/collapse in CSS. Its absence means the folder cannot be
	//     expanded — the banner is the sole trust affordance.
	//
	//     The closing-quote anchor `tree-node-has-children"` scopes the match to
	//     an attribute value, not the CSS stylesheet which references the class
	//     as a selector (`.tree-node-has-children {`). A bare NotContains on
	//     the full class name would be a false pass because the selector string
	//     appears in the embedded <style> block.
	assert.NotContains(t, html, `tree-node-has-children"`,
		"untrusted folder must not have tree-node-has-children — no chevron, no expand")
}

func TestTreeHtmlRenderer_ContainsIE11CompatMeta(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	html := renderer.RenderTreeView(TreeViewData{})

	assert.Contains(t, html, `X-UA-Compatible`)
	assert.Contains(t, html, `IE=edge`)
}

func TestTreeHtmlRenderer_ProductNodes_Rendered(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
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
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
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
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
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

	assert.Contains(t, html, "IGNORED")
}

func TestTreeHtmlRenderer_IssueBadges_PrependedBeforeLabel(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
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

	// Order: ignored < fixable < label < new (new badge appears after label)
	assert.Less(t, ignoredIdx, labelIdx, "ignored badge should come before label")
	assert.Less(t, fixableIdx, labelIdx, "fixable badge should come before label")
	assert.Less(t, ignoredIdx, fixableIdx, "ignored should come before fixable")
	assert.Less(t, labelIdx, newIdx, "new badge should come after label")
}

func TestTreeHtmlRenderer_NoGlobalScanningBanner(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	html := renderer.RenderTreeView(TreeViewData{})

	assert.NotContains(t, html, `id="scanStatus"`, "global scanning banner should not exist; scanning is per-product")
}

func TestTreeHtmlRenderer_FilterToolbar_SeverityButtons_Rendered(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
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

func TestTreeHtmlRenderer_FilterToolbar_PopoverHiddenWhenFlagsOff(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	html := renderer.RenderTreeView(TreeViewData{
		FilterState: TreeViewFilterState{
			SeverityFilter: types.DefaultSeverityFilter(),
			// ShowFilterPopover defaults to false (no feature flag enabled).
		},
	})

	// The funnel button and popover markup must be absent. We match on the
	// double-quoted attribute markup (id="filtersPopover"), which appears only in
	// the rendered body — the embedded tree.js references these ids via
	// getElementById('filtersPopover'), so a bare substring match would false-hit.
	assert.NotContains(t, html, `id="filtersPopover"`, "popover panel must not render when flags are off")
	assert.NotContains(t, html, `id="filtersPopoverBtn"`, "funnel button must not render when flags are off")
}

func TestTreeHtmlRenderer_FilterToolbar_Popover_RiskScoreOnly(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	html := renderer.RenderTreeView(TreeViewData{
		FilterState: TreeViewFilterState{
			SeverityFilter:     types.DefaultSeverityFilter(),
			RiskScoreThreshold: 500,
			RiskScoreEnabled:   true,
			ShowFilterPopover:  true,
		},
	})

	assert.Contains(t, html, `id="filtersPopoverBtn"`, "funnel button renders when a section is enabled")
	assert.Contains(t, html, `id="riskScoreSlider"`, "risk-score slider renders when RiskScoreEnabled")
	assert.Contains(t, html, `value="500"`, "slider reflects the aggregated threshold")
	assert.Contains(t, html, `≥ 500`, "value label reflects the threshold")
	// Issue-view section is gated off.
	assert.NotContains(t, html, `data-filter-value="ignoredIssues"`, "issue-view toggles absent when IssueViewOptionsEnabled is false")
}

func TestTreeHtmlRenderer_FilterToolbar_Popover_MixedState(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	html := renderer.RenderTreeView(TreeViewData{
		FilterState: TreeViewFilterState{
			SeverityFilter:          types.DefaultSeverityFilter(),
			RiskScoreEnabled:        true,
			RiskScoreMixed:          true,
			RiskScoreThreshold:      800, // highest folder threshold when mixed
			IssueViewOptionsEnabled: true,
			// aggregateIssueViewOptions pins a mixed option to false, so the
			// rendered open-issues checkbox is unchecked (+ indeterminate). The
			// native first click then flips it false→true = "enable everywhere".
			IssueViewOptions:      types.NewIssueViewOptions(false, false),
			MixedIssueViewOptions: MixedIssueViewOptions{OpenIssues: true},
			ShowFilterPopover:     true,
		},
	})

	assert.Contains(t, html, `filters-popover-trigger-mixed`, "funnel shows the mixed dot when any control is mixed")
	assert.Contains(t, html, `Mixed (≥ 800)`, "mixed risk-score label shows the highest folder threshold")
	assert.Contains(t, html, `value="800"`, "slider sits at the highest folder threshold when mixed")
	assert.Contains(t, html, `data-mixed="true"`, "the disagreeing open-issues checkbox carries data-mixed")
	// The mixed open-issues checkbox must render unchecked so the native first
	// click flips it to checked/true; assert the exact attribute sequence with
	// no intervening ` checked`.
	assert.Contains(t, html, `data-filter-value="openIssues" data-mixed="true">`,
		"mixed open-issues checkbox renders unchecked so first click enables everywhere")
}

func TestTreeHtmlRenderer_FilterToolbar_ExpandCollapseButtons_NotRendered(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	html := renderer.RenderTreeView(TreeViewData{})

	// The toolbar has no Expand/Collapse All buttons; per-scanner chevrons
	// handle expand/collapse.
	assert.NotContains(t, html, `id="expandAllBtn"`)
	assert.NotContains(t, html, `id="collapseAllBtn"`)
}

func TestTreeHtmlRenderer_MultiRoot_FolderNodes_Rendered(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
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

func TestTreeHtmlRenderer_ProductNode_ScanError_HasDataAttribute(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	errMsg := "dependency graph failed"
	productNode := NewTreeNode(NodeTypeProduct, "Open Source",
		WithProduct(product.ProductOpenSource),
		WithDescription("- (scan failed)"),
		WithErrorMessage(errMsg),
	)

	html := renderer.RenderTreeView(TreeViewData{
		Nodes: []TreeNode{productNode},
	})

	assert.Contains(t, html, `data-error-message="dependency graph failed"`, "product node with error should have data-error-message attribute")
	assert.Contains(t, html, "tree-node-error", "product node with error should have error CSS class")
}

func TestTreeHtmlRenderer_ProductNode_HasChildrenClass_OnlyWhenExpandable(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	// The chevron glyph is gated on tree-node-has-children, so a product with
	// children (completed scan with results/info rows) carries the class and one
	// without (scanning / awaiting first scan / errored) does not.
	withChildren := NewTreeNode(NodeTypeProduct, "Open Source",
		WithProduct(product.ProductOpenSource),
		WithChildren([]TreeNode{NewTreeNode(NodeTypeInfo, "✅ No issues found")}),
	)
	withoutChildren := NewTreeNode(NodeTypeProduct, "Snyk Code",
		WithProduct(product.ProductCode),
		WithDescription("- Scanning..."),
	)

	withHTML := renderer.RenderTreeView(TreeViewData{Nodes: []TreeNode{withChildren}})
	withoutHTML := renderer.RenderTreeView(TreeViewData{Nodes: []TreeNode{withoutChildren}})

	// Match the class on the node (space-separated, quote-terminated) rather than
	// the bare string, which also appears in the embedded styles.css selectors.
	assert.Contains(t, withHTML, ` tree-node-has-children"`, "product with children should be marked expandable")
	assert.NotContains(t, withoutHTML, ` tree-node-has-children"`, "product without children should not be marked expandable")
}

func TestTreeHtmlRenderer_FolderNode_DeltaEnabled_HasBranchDataAttributes(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	folderNode := NewTreeNode(NodeTypeFolder, "project",
		WithID("folder:/project"),
		WithFilePath("/project"),
		WithDeltaEnabled(true),
		WithBaseBranch("main"),
		WithLocalBranches([]string{"main", "develop", "feature-x"}),
		WithDescription("base: main"),
		WithChildren([]TreeNode{
			NewTreeNode(NodeTypeProduct, "Snyk Code"),
		}),
	)

	html := renderer.RenderTreeView(TreeViewData{
		Nodes: []TreeNode{folderNode},
	})

	assert.Contains(t, html, `data-delta-enabled="true"`, "delta-enabled folder should have data-delta-enabled attribute")
	assert.Contains(t, html, `data-base-branch="main"`, "folder node should have data-base-branch attribute")
	assert.Contains(t, html, `data-local-branches="main,develop,feature-x"`, "folder node should have data-local-branches attribute")
}

func TestTreeHtmlRenderer_FolderNode_DeltaEnabled_ReferenceFolderPath(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	folderNode := NewTreeNode(NodeTypeFolder, "project",
		WithID("folder:/project"),
		WithFilePath("/project"),
		WithDeltaEnabled(true),
		WithReferenceFolderPath("/other/project"),
		WithDescription("ref: /other/project"),
		WithChildren([]TreeNode{
			NewTreeNode(NodeTypeProduct, "Snyk Code"),
		}),
	)

	html := renderer.RenderTreeView(TreeViewData{
		Nodes: []TreeNode{folderNode},
	})

	assert.Contains(t, html, `data-reference-folder-path="/other/project"`, "folder node should have data-reference-folder-path attribute")
	assert.NotContains(t, html, `data-base-branch="`, "no base branch should be present when reference folder is set")
}

func TestTreeHtmlRenderer_FolderNode_DeltaDisabled_NoBranchDataAttributes(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	folderNode := NewTreeNode(NodeTypeFolder, "project",
		WithID("folder:/project"),
		WithFilePath("/project"),
		WithChildren([]TreeNode{
			NewTreeNode(NodeTypeProduct, "Snyk Code"),
		}),
	)

	html := renderer.RenderTreeView(TreeViewData{
		Nodes:     []TreeNode{folderNode},
		MultiRoot: true,
	})

	assert.NotContains(t, html, `data-delta-enabled="true"`, "non-delta folder should not have data-delta-enabled attribute")
	assert.NotContains(t, html, `data-base-branch="`, "non-delta folder should not have data-base-branch attribute")
	assert.NotContains(t, html, `data-local-branches="`, "non-delta folder should not have data-local-branches attribute")
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

func TestTreeHtmlRenderer_NodeLabelsWithHtmlSpecialChars_AreEscaped(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	maliciousLabel := `<script>alert("xss")</script>`
	maliciousDesc := `<img src=x onerror=alert(1)>`
	enabled := true

	data := TreeViewData{
		Nodes: []TreeNode{
			NewTreeNode(NodeTypeProduct, maliciousLabel,
				WithID("product:xss"),
				WithDescription(maliciousDesc),
				WithEnabled(&enabled),
				WithChildren([]TreeNode{
					NewTreeNode(NodeTypeFile, maliciousLabel,
						WithID("file:xss:/evil.go"),
						WithFilePath(types.FilePath("/evil.go")),
						WithChildren([]TreeNode{
							NewTreeNode(NodeTypeIssue, maliciousLabel,
								WithID("issue:xss-1"),
								WithFilePath(types.FilePath("/evil.go")),
								WithSeverity(types.High),
							),
						}),
					),
				}),
			),
		},
	}

	html := renderer.RenderTreeView(data)
	assert.NotContains(t, html, `<script>alert`, "script tags in labels must be escaped")
	assert.NotContains(t, html, `<img src=x`, "img tags in descriptions must be escaped")
	assert.Contains(t, html, `&lt;script&gt;`, "label should contain escaped HTML entities")
	assert.Contains(t, html, `&lt;img`, "description should contain escaped img tag")
}

// TestTreeHtmlRenderer_UntrustedFolderPaths_AreHtmlEscapedInBanner verifies that
// folder paths rendered inside the untrusted-folder banner are HTML-escaped. The
// paths appear in data-folder-path="..." attribute values and in the visible label
// span. A path containing " or < must not produce unescaped HTML that an attacker
// could inject into the webview. Go's html/template escapes attribute values
// automatically; this test proves the guarantee holds end-to-end. (IDE-1882)
func TestTreeHtmlRenderer_UntrustedFolderPaths_AreHtmlEscapedInBanner(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	// A path that contains both HTML-special characters:
	//   " breaks attribute value quoting
	//   < could open a tag
	maliciousPath := `/repo/my"project</script><script>alert(1)`

	banner := NewTreeNode(NodeTypeInfo, untrustedFolderRationale,
		WithID("info:untrusted-folder"),
		WithInfoVariant("untrusted-folder"),
		WithFolderPaths([]string{maliciousPath}),
	)

	html := renderer.RenderTreeView(TreeViewData{Nodes: []TreeNode{banner}})

	// The raw path must never appear verbatim in the HTML output.
	assert.NotContains(t, html, maliciousPath,
		"raw malicious path must not appear unescaped in the banner HTML")

	// The double-quote and angle brackets must be escaped as HTML entities in the
	// data-folder-path attribute and the visible label.
	assert.Contains(t, html, `&#34;`, "double-quote in folder path must be escaped as &#34; in attributes")
	assert.NotContains(t, html, `<script>alert(1)`,
		"script injection via folder path must be neutralized by HTML escaping")
}

func TestTreeHtmlRenderer_LocationNode_HasDataAttributesAndClass(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	locNode := NewTreeNode(NodeTypeLocation, "config.yml",
		WithID("location:fp-001:0"),
		WithSeverity(types.High),
		WithIssueID("key-loc1"),
		WithFilePath("/project/config.yml"),
		WithIssueRange(types.Range{
			Start: types.Position{Line: 9, Character: 4},
			End:   types.Position{Line: 9, Character: 24},
		}),
		WithDescription("[10,5]"),
	)
	issueGroupNode := NewTreeNode(NodeTypeIssue, "AWS Access Token",
		WithID("issue:fp-001"),
		WithSeverity(types.High),
		WithChildren([]TreeNode{locNode}),
	)
	fileNode := NewTreeNode(NodeTypeFile, "config.yml",
		WithChildren([]TreeNode{issueGroupNode}),
	)
	productNode := NewTreeNode(NodeTypeProduct, "Secrets",
		WithChildren([]TreeNode{fileNode}),
	)

	html := renderer.RenderTreeView(TreeViewData{Nodes: []TreeNode{productNode}})

	assert.Contains(t, html, "tree-node-location", "location node should have tree-node-location class")
	assert.Contains(t, html, `data-issue-id="key-loc1"`)
	assert.Contains(t, html, `data-start-line="9"`)
	assert.Contains(t, html, `data-end-line="9"`)
	assert.Contains(t, html, `data-start-char="4"`)
	assert.Contains(t, html, `data-end-char="24"`)
	assert.Contains(t, html, "[10,5]", "location node description should contain range suffix")
}

func TestTreeHtmlRenderer_IssueGroupNode_RendersAsExpandableContainer(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	locNode := NewTreeNode(NodeTypeLocation, "config.yml",
		WithID("location:fp-001:0"),
		WithSeverity(types.High),
		WithIssueID("key-loc1"),
		WithFilePath("/project/config.yml"),
		WithDescription("[10,5]"),
	)
	issueGroupNode := NewTreeNode(NodeTypeIssue, "AWS Access Token",
		WithID("issue:fp-001"),
		WithSeverity(types.High),
		WithChildren([]TreeNode{locNode}),
	)
	fileNode := NewTreeNode(NodeTypeFile, "config.yml",
		WithChildren([]TreeNode{issueGroupNode}),
	)
	productNode := NewTreeNode(NodeTypeProduct, "Secrets",
		WithChildren([]TreeNode{fileNode}),
	)

	html := renderer.RenderTreeView(TreeViewData{Nodes: []TreeNode{productNode}})

	assert.Contains(t, html, "tree-node-issue-group", "issue with children should render as issue-group")
	assert.NotContains(t, html, `class="tree-node tree-node-issue"`, "issue with children should NOT render as plain issue leaf")
	assert.Contains(t, html, "tree-node-children", "issue-group should have a children container")
	assert.Contains(t, html, "AWS Access Token")
}

func TestTreeHtmlRenderer_IssueLeafNode_NoChildrenContainer(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	issueNode := NewTreeNode(NodeTypeIssue, "SQL Injection",
		WithID("issue:rule-1"),
		WithSeverity(types.High),
		WithIssueID("key-single"),
	)
	fileNode := NewTreeNode(NodeTypeFile, "main.go",
		WithChildren([]TreeNode{issueNode}),
	)
	productNode := NewTreeNode(NodeTypeProduct, "Code",
		WithChildren([]TreeNode{fileNode}),
	)

	html := renderer.RenderTreeView(TreeViewData{Nodes: []TreeNode{productNode}})

	assert.Contains(t, html, `class="tree-node tree-node-issue"`, "issue without children should render as plain leaf")
	assert.NotContains(t, html, `class="tree-node tree-node-issue-group`, "issue without children should NOT render as group element")
}

func TestCheckmarkSVG_ReturnsGreenCheckmark(t *testing.T) {
	svg := checkmarkSVG()
	assert.Contains(t, svg, "#368746", "checkmark should have green color")
	assert.Contains(t, svg, "<svg")
}

func TestTreeHtmlRenderer_FileNode_NoEmoji(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	fileNode := NewTreeNode(NodeTypeFile, "main.go",
		WithFileIconHTML(`<svg>file</svg>`),
	)
	productNode := NewTreeNode(NodeTypeProduct, "Code",
		WithProduct(product.ProductCode),
		WithChildren([]TreeNode{fileNode}),
	)

	html := renderer.RenderTreeView(TreeViewData{Nodes: []TreeNode{productNode}})

	assert.NotContains(t, html, "📄", "file node should not render emoji")
}

func TestTreeHtmlRenderer_FileNode_WithFileIconHTML_RendersIcon(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	fileNode := NewTreeNode(NodeTypeFile, "package.json",
		WithFileIconHTML(`<svg class="npm-icon">npm</svg>`),
	)
	productNode := NewTreeNode(NodeTypeProduct, "Open Source",
		WithProduct(product.ProductOpenSource),
		WithChildren([]TreeNode{fileNode}),
	)

	html := renderer.RenderTreeView(TreeViewData{Nodes: []TreeNode{productNode}})

	assert.Contains(t, html, `class="npm-icon"`, "inline file icon HTML should appear in output")
}

func TestTreeHtmlRenderer_IssueGroupNode_ShowsLocationCountAndChevron(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	loc1 := NewTreeNode(NodeTypeLocation, "[1,1]",
		WithID("location:fp1:0"),
		WithSeverity(types.High),
		WithFilePath("/project/main.go"),
		WithIssueRange(types.Range{Start: types.Position{Line: 0, Character: 0}}),
	)
	loc2 := NewTreeNode(NodeTypeLocation, "[5,3]",
		WithID("location:fp1:1"),
		WithSeverity(types.High),
		WithFilePath("/project/main.go"),
		WithIssueRange(types.Range{Start: types.Position{Line: 4, Character: 2}}),
	)
	issueGroup := NewTreeNode(NodeTypeIssue, "Hardcoded Secret",
		WithID("issue:fp1"),
		WithSeverity(types.High),
		WithDescription("2 locations"),
		WithChildren([]TreeNode{loc1, loc2}),
	)
	fileNode := NewTreeNode(NodeTypeFile, "main.go",
		WithChildren([]TreeNode{issueGroup}),
	)
	productNode := NewTreeNode(NodeTypeProduct, "Snyk Code",
		WithProduct(product.ProductCode),
		WithChildren([]TreeNode{fileNode}),
	)

	html := renderer.RenderTreeView(TreeViewData{Nodes: []TreeNode{productNode}})

	assert.Contains(t, html, "tree-node-issue-group", "issue group node should have group class")
	assert.Contains(t, html, "2 locations", "issue group node should show location count in description")
	assert.Contains(t, html, "tree-chevron", "issue group node must have a chevron for expand/collapse")
}

func TestTreeHtmlRenderer_FileNode_EmptyFileIconHTML_RendersGenericSVG(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	fileNode := NewTreeNode(NodeTypeFile, "main.go")
	productNode := NewTreeNode(NodeTypeProduct, "Code",
		WithProduct(product.ProductCode),
		WithChildren([]TreeNode{fileNode}),
	)

	html := renderer.RenderTreeView(TreeViewData{Nodes: []TreeNode{productNode}})

	assert.NotContains(t, html, "📄", "empty FileIconHTML should not fall back to emoji")
	assert.Contains(t, html, `<svg`, "empty FileIconHTML should render the generic file SVG")
}

// TestTreeHtmlRenderer_MixedSeverity_RendersMixedClass verifies that when a severity is mixed
// (open folders disagree), the toolbar button carries filter-mixed and the correct tooltip text
// (tree.html:33-36).
func TestTreeHtmlRenderer_MixedSeverity_RendersMixedClass(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	html := renderer.RenderTreeView(TreeViewData{
		FilterState: TreeViewFilterState{
			SeverityFilter: types.DefaultSeverityFilter(),
			MixedSeverity:  MixedSeverity{Critical: true},
		},
	})

	assert.Contains(t, html, `filter-mixed`, "critical button should carry filter-mixed class when severity disagrees across folders")
	assert.Contains(t, html, `Open folders use different Critical severity filters`, "mixed critical button should carry the expected tooltip")
}

// TestTreeHtmlRenderer_ProductNode_Tooltip_RenderedAsTitle verifies that a node with .Tooltip
// set produces a title="..." attribute on the row element (tree.html:70).
func TestTreeHtmlRenderer_ProductNode_Tooltip_RenderedAsTitle(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	productNode := NewTreeNode(NodeTypeProduct, "Snyk Code",
		WithProduct(product.ProductCode),
		WithTooltip("Snyk Code is disabled"),
	)

	html := renderer.RenderTreeView(TreeViewData{Nodes: []TreeNode{productNode}})

	assert.Contains(t, html, `title="Snyk Code is disabled"`, "node tooltip should render as title attribute on the row element")
}

// TestTreeHtmlRenderer_ProductNode_HasDataProductID verifies that data-product-id is present
// on a product node and carries the product codename (tree.html:69).
func TestTreeHtmlRenderer_ProductNode_HasDataProductID(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	productNode := NewTreeNode(NodeTypeProduct, "Snyk Code",
		WithProduct(product.ProductCode),
	)

	html := renderer.RenderTreeView(TreeViewData{Nodes: []TreeNode{productNode}})

	assert.Contains(t, html, `data-product-id="code"`, "product node should carry data-product-id with codename")
}

// TestTreeHtmlRenderer_ProductNode_HasAbbreviatedIconClass verifies that product-icon--abbreviated
// class is present on the product icon (tree.html:72).
func TestTreeHtmlRenderer_ProductNode_HasAbbreviatedIconClass(t *testing.T) {
	engine := testutil.UnitTest(t)
	renderer, err := NewTreeHtmlRenderer(engine.GetLogger())
	require.NoError(t, err)

	productNode := NewTreeNode(NodeTypeProduct, "Open Source",
		WithProduct(product.ProductOpenSource),
	)

	html := renderer.RenderTreeView(TreeViewData{Nodes: []TreeNode{productNode}})

	assert.Contains(t, html, `product-icon--abbreviated`, "product icon should carry the product-icon--abbreviated class")
}
