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
	"path/filepath"
	"sort"
	"strings"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/utils"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

// FolderData contains pre-fetched data for a workspace folder, decoupling the builder
// from the folder interface and making it testable without requiring full folder mocks.
type FolderData struct {
	FolderPath               types.FilePath
	FolderName               string
	SupportedIssueTypes      map[product.FilterableIssueType]bool
	AllIssues                snyk.IssuesByFile
	FilteredIssues           snyk.IssuesByFile
	DeltaEnabled             bool
	BaseBranch               string
	LocalBranches            []string
	ReferenceFolderPath      string
	IssueViewOptions         types.IssueViewOptions
	ConsistentIgnoresEnabled bool
	// AgentFixEnabled reports whether Snyk Agent Fix (Code autofix) is enabled for
	// this folder's SAST settings. It gates the Snyk Code product's "fixable" info
	// line: when Agent Fix is off we hide the line entirely rather than surface a
	// fix the user cannot action.
	AgentFixEnabled bool
}

// fileIconProvider is satisfied by issue data types that can supply a file-node icon
// (currently only OssIssueData). Decouples the builder from concrete types.
type fileIconProvider interface {
	GetFileIcon(filePath string) string
}

// maxAutoExpandIssues is the threshold below which file nodes auto-expand.
// Auto-expand is handled entirely server-side in resolveExpanded.
const maxAutoExpandIssues = 50

// TreeBuilder constructs a TreeViewData hierarchy from workspace folder data.
type TreeBuilder struct {
	expandState       *ExpandState
	totalIssues       int // set during BuildTreeFromFolderData for auto-expand decisions
	productScanStates map[types.FilePath]map[product.Product]bool
	productScanErrors map[types.FilePath]map[product.Product]string
	pendingAutoExpand map[string]bool // deferred auto-expand writes applied after build
}

// NewTreeBuilder creates a new TreeBuilder with the given expand state.
// If expandState is nil, default expand behavior is used (folder/product expanded, file collapsed).
func NewTreeBuilder(expandState ...*ExpandState) *TreeBuilder {
	var es *ExpandState
	if len(expandState) > 0 && expandState[0] != nil {
		es = expandState[0]
	}
	return &TreeBuilder{expandState: es}
}

// SetProductScanStates sets the per-(folder, product) scan-in-progress state.
func (b *TreeBuilder) SetProductScanStates(states map[types.FilePath]map[product.Product]bool) {
	b.productScanStates = states
}

// SetProductScanErrors sets the per-(folder, product) scan error messages.
func (b *TreeBuilder) SetProductScanErrors(errors map[types.FilePath]map[product.Product]string) {
	b.productScanErrors = errors
}

// BuildTree constructs tree view data from a workspace.
func (b *TreeBuilder) BuildTree(workspace types.Workspace) TreeViewData {
	folders := workspace.Folders()
	if len(folders) == 0 {
		return TreeViewData{}
	}

	var folderDataList []FolderData
	for _, f := range folders {
		fip, ok := f.(snyk.FilteringIssueProvider)
		if !ok {
			continue
		}
		// Fetch FolderConfig once; all derived values are computed from this single call
		// to avoid repeated storage reads inside DisplayableIssueTypes, IsDeltaFindingsEnabled,
		// and IssueViewOptions (each would otherwise invoke FolderConfigReadOnly separately).
		cfg := f.FolderConfigReadOnly()
		supportedTypes := f.DisplayableIssueTypesFromConfig(cfg)
		allIssues := fip.Issues()
		filtered := fip.FilterIssues(allIssues, supportedTypes)

		fd := FolderData{
			FolderPath:          f.Path(),
			FolderName:          f.Name(),
			SupportedIssueTypes: supportedTypes,
			AllIssues:           allIssues,
			FilteredIssues:      filtered,
			DeltaEnabled:        f.IsDeltaFindingsEnabledFromConfig(cfg),
			IssueViewOptions:    f.IssueViewOptionsFromConfig(cfg),
		}
		if cfg != nil {
			fd.ConsistentIgnoresEnabled = cfg.GetFeatureFlag(featureflag.SnykCodeConsistentIgnores)
			if conf := cfg.Conf(); conf != nil {
				// Agent Fix is gated per-folder here (each folder's Code node reflects its
				// own SAST settings). This intentionally differs from the summary panel,
				// which is workspace-wide and uses any-folder enablement
				// (scanstates.HtmlRenderer.isAutofixEnabledInAnyFolder); in a multi-root
				// workspace with mixed settings the two surfaces can legitimately disagree.
				// Absent/nil SAST settings deliberately fall through to AgentFixEnabled=false
				// (unknown == hidden). This is safe: the fixable line only renders after a
				// completed Code scan (see buildProductNodes' enabled/scanRegistered gate),
				// which cannot succeed without SAST settings being populated first.
				if sast := types.GetSastSettings(conf, cfg.FolderPath); sast != nil {
					fd.AgentFixEnabled = sast.AutofixEnabled
				}

				if fd.DeltaEnabled {
					snapshot := types.ReadFolderConfigSnapshot(conf, cfg.FolderPath)
					fd.BaseBranch = snapshot.BaseBranch
					fd.LocalBranches = snapshot.LocalBranches
					fd.ReferenceFolderPath = string(snapshot.ReferenceFolderPath)
				}
			}
		}
		folderDataList = append(folderDataList, fd)
	}

	return b.BuildTreeFromFolderData(folderDataList)
}

// BuildTreeFromFolderData builds the tree from pre-fetched folder data.
func (b *TreeBuilder) BuildTreeFromFolderData(folders []FolderData) TreeViewData {
	b.pendingAutoExpand = nil
	multiRoot := len(folders) > 1
	data := TreeViewData{
		MultiRoot: multiRoot,
	}

	totalIssues := 0
	for _, fd := range folders {
		allFolderIssues := flattenIssues(fd.FilteredIssues)
		totalIssues += len(types.DeduplicateByFingerprint(allFolderIssues))
	}
	data.TotalIssues = totalIssues
	b.totalIssues = totalIssues

	// Show folder nodes when multi-root OR single-folder with delta enabled.
	// In IntelliJ native tree, the folder node is hidden in single-folder mode unless
	// delta is enabled (the folder node is needed for reference folder selection).
	showFolderNodes := multiRoot || (len(folders) == 1 && folders[0].DeltaEnabled)

	if showFolderNodes {
		for _, folder := range folders {
			folderID := fmt.Sprintf("folder:%s", folder.FolderPath)
			opts := []TreeNodeOption{
				WithID(folderID),
				WithExpanded(b.resolveExpanded(folderID, NodeTypeFolder)),
				WithFilePath(folder.FolderPath),
				WithChildren(b.buildProductNodes(folder)),
			}
			if folder.DeltaEnabled {
				opts = append(opts, WithDeltaEnabled(true))
				if len(folder.LocalBranches) > 0 {
					opts = append(opts, WithLocalBranches(folder.LocalBranches))
				}
				// Only one of BaseBranch or ReferenceFolderPath is set on the node.
				// ReferenceFolderPath takes precedence when both are present in FolderData.
				if folder.ReferenceFolderPath != "" {
					opts = append(opts, WithDescription(fmt.Sprintf("ref: %s", folder.ReferenceFolderPath)))
					opts = append(opts, WithReferenceFolderPath(folder.ReferenceFolderPath))
				} else if folder.BaseBranch != "" {
					opts = append(opts, WithDescription(fmt.Sprintf("base: %s", folder.BaseBranch)))
					opts = append(opts, WithBaseBranch(folder.BaseBranch))
				}
			}
			folderNode := NewTreeNode(NodeTypeFolder, folder.FolderName, opts...)
			data.Nodes = append(data.Nodes, folderNode)
		}
	} else if len(folders) == 1 {
		data.Nodes = b.buildProductNodes(folders[0])
	}

	if b.expandState != nil {
		for nodeID, expanded := range b.pendingAutoExpand {
			b.expandState.Set(nodeID, expanded)
		}
	}
	b.pendingAutoExpand = nil

	return data
}

// buildProductNodes creates product-level nodes for a single folder's issues.
// All known products are emitted (even with 0 issues) so the UI can show "No issues found".
func (b *TreeBuilder) buildProductNodes(fd FolderData) []TreeNode {
	// Group filtered issues by product
	issuesByProduct := make(map[product.Product]snyk.IssuesByFile)
	for path, issues := range fd.FilteredIssues {
		for _, issue := range issues {
			p := issue.GetProduct()
			if issuesByProduct[p] == nil {
				issuesByProduct[p] = make(snyk.IssuesByFile)
			}
			issuesByProduct[p][path] = append(issuesByProduct[p][path], issue)
		}
	}

	// Group unfiltered issues by product too, so we can tell when the active
	// filters are hiding every issue for a product (→ filter-aware empty state).
	allByProduct := make(map[product.Product]snyk.IssuesByFile)
	for path, issues := range fd.AllIssues {
		for _, issue := range issues {
			p := issue.GetProduct()
			if allByProduct[p] == nil {
				allByProduct[p] = make(snyk.IssuesByFile)
			}
			allByProduct[p][path] = append(allByProduct[p][path], issue)
		}
	}

	// Product ordering matches native IntelliJ tree: Open Source → Code Security Infrastructure As Code + Secrets
	productOrder := []product.Product{
		product.ProductOpenSource,
		product.ProductCode,
		product.ProductInfrastructureAsCode,
		product.ProductSecrets,
	}

	var productNodes []TreeNode
	for _, p := range productOrder {
		pIssues := issuesByProduct[p]
		allIssues := flattenIssues(pIssues)
		stats := computeIssueStats(allIssues)
		totalIssues := len(stats.uniqueIssues)

		// True when this scanner has findings but the active filters hide them all.
		unfilteredCount := len(computeIssueStats(flattenIssues(allByProduct[p])).uniqueIssues)
		hiddenByFilter := totalIssues == 0 && unfilteredCount > 0

		// Determine whether this product is enabled via SupportedIssueTypes
		enabled := isProductEnabled(p, fd.SupportedIssueTypes)

		// Determine scan state for this (folder, product) pair:
		// - key absent → no scan registered yet (initial state)
		// - key present + true → scan in progress
		// - key present + false → scan completed
		scanning, scanRegistered := false, false
		if folderStates := b.productScanStates[fd.FolderPath]; folderStates != nil {
			scanning, scanRegistered = folderStates[p]
		}

		// Check for scan errors scoped to this folder
		var scanError string
		if folderErrors := b.productScanErrors[fd.FolderPath]; folderErrors != nil {
			scanError = folderErrors[p]
		}

		// Build description with severity breakdown (matching IntelliJ native tree)
		var desc string
		if !enabled {
			desc = "(disabled in Settings)"
		} else if scanning {
			if totalIssues == 0 {
				desc = "- Scanning..."
			} else {
				desc = "- " + productDescription(p, totalIssues, stats.severityCounts) + " (scanning...)"
			}
		} else if scanError != "" {
			desc = productScanErrorDescription(scanError)
		} else if scanRegistered {
			if totalIssues == 0 {
				// Zero visible issues: the row shows just a ✅ tick (with a
				// "No issues found" tooltip). The explanatory text — including the
				// filter-aware variant — lives on the expandable child info node.
				desc = "✅"
			} else {
				desc = "- " + productDescription(p, totalIssues, stats.severityCounts)
			}
		}
		// else: no scan registered yet → empty description (initial state)

		// Hover tooltip explaining a non-running scanner. The copy is tailored to
		// *why* it isn't running so the user knows what (if anything) they can do
		// about it. Mirrors the description precedence above (settings-disabled
		// wins over error, since a product turned off in settings never scans).
		var tooltip string
		if !enabled {
			tooltip = productSettingsDisabledTooltip(p)
		} else if scanError != "" {
			tooltip = productDisabledTooltip(p, scanError)
		} else if scanRegistered && !scanning && totalIssues == 0 {
			// Surfaces the ✅ tick's meaning on hover; the child node carries any
			// filter-aware detail.
			tooltip = "No issues found"
		}

		// Build children: info nodes first, then file nodes (only for enabled products with completed scans)
		productKey := fmt.Sprintf("product:%s:%s", fd.FolderPath, p)
		var children []TreeNode
		if enabled && scanRegistered && !scanning && scanError == "" {
			children = append(children, b.buildInfoNodes(infoNodeContext{
				product:                  p,
				parentKey:                productKey,
				totalIssues:              totalIssues,
				fixableCount:             stats.fixableCount,
				ignoredCount:             stats.ignoredCount,
				issueViewOptions:         fd.IssueViewOptions,
				consistentIgnoresEnabled: fd.ConsistentIgnoresEnabled,
				agentFixEnabled:          fd.AgentFixEnabled,
				hiddenByFilter:           hiddenByFilter,
			})...)

			if totalIssues > 0 {
				children = append(children, b.buildFileNodes(pIssues, fd.FolderPath, p)...)
			}
		}

		productID := fmt.Sprintf("product:%s:%s", fd.FolderPath, p)
		productNode := NewTreeNode(NodeTypeProduct, productDisplayName(p),
			WithID(productID),
			WithExpanded(b.resolveExpanded(productID, NodeTypeProduct)),
			WithProduct(p),
			WithDescription(desc),
			WithSeverityCounts(stats.severityCounts),
			WithFixableCount(stats.fixableCount),
			WithIssueCount(totalIssues),
			WithEnabled(&enabled),
			WithErrorMessage(scanError),
			WithTooltip(tooltip),
			WithChildren(children),
		)
		productNodes = append(productNodes, productNode)
	}

	return productNodes
}

// productDisplayName returns the user-facing product name for the tree view,
// matching the native IntelliJ tree label (FilterableIssueType names).
func productDisplayName(p product.Product) string {
	return p.ToProductNamesString()
}

// isProductEnabled checks whether a product is enabled in the given supported issue types map.
func isProductEnabled(p product.Product, supportedTypes map[product.FilterableIssueType]bool) bool {
	for _, ft := range p.ToFilterableIssueType() {
		if supportedTypes[ft] {
			return true
		}
	}
	return false
}

// infoNodeContext carries the data needed to build info child nodes for a product.
type infoNodeContext struct {
	product                  product.Product
	parentKey                string
	totalIssues              int
	fixableCount             int
	ignoredCount             int
	issueViewOptions         types.IssueViewOptions
	consistentIgnoresEnabled bool
	// agentFixEnabled reflects FolderData.AgentFixEnabled; only consulted for the
	// Snyk Code product (see showFixableLine).
	agentFixEnabled bool
	// hiddenByFilter is true when the scanner has issues but the active filters
	// hide all of them, so the empty-state text reads "...with these filters".
	hiddenByFilter bool
}

// buildInfoNodes creates info child nodes for a product, matching IntelliJ addInfoTreeNodes().
func (b *TreeBuilder) buildInfoNodes(ctx infoNodeContext) []TreeNode {
	var infoNodes []TreeNode

	if ctx.totalIssues == 0 {
		// Single empty-state row. zeroIssuesText already conveys the filter/
		// issue-view situation ("No issues found", "...with these filters",
		// "...open issues are disabled"), so no separate "Adjust your settings"
		// hint is needed.
		infoNodes = append(infoNodes, NewTreeNode(NodeTypeInfo, b.zeroIssuesText(ctx),
			WithID(fmt.Sprintf("info:%s:congrats", ctx.parentKey))))
	} else {
		infoNodes = append(infoNodes, NewTreeNode(NodeTypeInfo, b.issueCountText(ctx),
			WithID(fmt.Sprintf("info:%s:count", ctx.parentKey))))

		// Fixable line — only shown for scanners where automatic fixing is something
		// the user can action (see showFixableLine).
		if showFixableLine(ctx) {
			if ctx.fixableCount > 0 {
				fixWord := "issues are"
				if ctx.fixableCount == 1 {
					fixWord = "issue is"
				}
				infoNodes = append(infoNodes, NewTreeNode(NodeTypeInfo,
					fmt.Sprintf("⚡ %d %s fixable automatically.", ctx.fixableCount, fixWord),
					WithID(fmt.Sprintf("info:%s:fixable", ctx.parentKey))))
			} else {
				infoNodes = append(infoNodes, NewTreeNode(NodeTypeInfo, "There are no issues automatically fixable.",
					WithID(fmt.Sprintf("info:%s:fixable", ctx.parentKey))))
			}
		}
	}

	return infoNodes
}

// showFixableLine decides whether a scanner's "fixable" info line is shown. We
// only surface it where automatic fixing is something the user can act on:
//   - Snyk Code: only when Agent Fix (autofix) is enabled for the folder. When it
//     is disabled the line is hidden entirely, since the "fixable automatically"
//     count is not actionable.
//   - Open Source: always — upgrade-based fixability is available whenever OSS
//     scanning runs, independent of Agent Fix.
//   - IaC / Secrets: never — they have no automatic-fix concept (IsFixable is
//     always false), so the line would only ever read "no issues automatically
//     fixable", which is noise.
//
// This switch encodes per-product fixability knowledge. When a new product or fix
// mechanism is added, update this switch — and keep it consistent with the
// summary panel's Agent-Fix logic (scanstates/summary_html.go), which makes the
// equivalent decision for the workspace-wide summary.
func showFixableLine(ctx infoNodeContext) bool {
	switch ctx.product {
	case product.ProductCode:
		return ctx.agentFixEnabled
	case product.ProductOpenSource:
		return true
	default:
		return false
	}
}

// zeroIssuesText is the label for the child info node shown under a scanner with
// no visible issues. No emoji — the ✅ tick lives on the parent scanner row; this
// is the explanatory text revealed on expand.
func (b *TreeBuilder) zeroIssuesText(ctx infoNodeContext) string {
	if ctx.hiddenByFilter {
		return "No issues found with these filters"
	}
	if !ctx.consistentIgnoresEnabled {
		return "No issues found"
	}
	ivo := ctx.issueViewOptions
	if ivo.OpenIssues && !ivo.IgnoredIssues {
		return "No open issues found"
	}
	if !ivo.OpenIssues && ivo.IgnoredIssues {
		return "No ignored issues, open issues are disabled"
	}
	if !ivo.OpenIssues && !ivo.IgnoredIssues {
		return "Open and Ignored issues are disabled!"
	}
	return "No issues found"
}

func (b *TreeBuilder) issueCountText(ctx infoNodeContext) string {
	if !ctx.consistentIgnoresEnabled {
		issueWord := "issues"
		if ctx.totalIssues == 1 {
			issueWord = "issue"
		}
		return fmt.Sprintf("✋ %d %s", ctx.totalIssues, issueWord)
	}
	openCount := ctx.totalIssues - ctx.ignoredCount
	ivo := ctx.issueViewOptions
	if ivo.OpenIssues && ivo.IgnoredIssues {
		if ctx.ignoredCount == 0 {
			return fmt.Sprintf("✋ %s", pluralize(openCount, "open issue"))
		}
		return fmt.Sprintf("✋ %s & %s",
			pluralize(openCount, "open issue"),
			pluralize(ctx.ignoredCount, "ignored issue"))
	}
	if ivo.OpenIssues {
		return fmt.Sprintf("✋ %s", pluralize(openCount, "open issue"))
	}
	if ivo.IgnoredIssues {
		return fmt.Sprintf("✋ %s, open issues are disabled",
			pluralize(ctx.ignoredCount, "ignored issue"))
	}
	return "Open and Ignored issues are disabled!"
}

func pluralize(count int, singular string) string {
	if count == 1 {
		return fmt.Sprintf("%d %s", count, singular)
	}
	return fmt.Sprintf("%d %ss", count, singular)
}

// productDescription builds the severity breakdown description for a product node.
// Only non-zero severity counts are included.
func productDescription(p product.Product, totalIssues int, counts *SeverityCounts) string {
	if totalIssues == 0 {
		return "No issues found"
	}

	word := countWord(totalIssues)
	var parts []string
	if counts.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", counts.Critical))
	}
	if counts.High > 0 {
		parts = append(parts, fmt.Sprintf("%d high", counts.High))
	}
	if counts.Medium > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", counts.Medium))
	}
	if counts.Low > 0 {
		parts = append(parts, fmt.Sprintf("%d low", counts.Low))
	}

	if len(parts) == 0 {
		return fmt.Sprintf("%d %s", totalIssues, word)
	}
	return fmt.Sprintf("%d %s: %s", totalIssues, word, strings.Join(parts, ", "))
}

// countWord returns the singular/plural noun for an issue count ("issue"/"issues").
func countWord(count int) string {
	if count == 1 {
		return "issue"
	}
	return "issues"
}

type issueStats struct {
	uniqueIssues   []types.Issue
	severityCounts *SeverityCounts
	fixableCount   int
	ignoredCount   int
}

// computeIssueStats deduplicates by fingerprint and computes all counts in a single pass.
func computeIssueStats(issues []types.Issue) issueStats {
	seen := make(map[string]bool, len(issues))
	stats := issueStats{severityCounts: &SeverityCounts{}}
	for _, issue := range issues {
		fp := issue.GetFingerprint()
		if fp != "" && seen[fp] {
			continue
		}
		if fp != "" {
			seen[fp] = true
		}
		stats.uniqueIssues = append(stats.uniqueIssues, issue)
		switch issue.GetSeverity() {
		case types.Critical:
			stats.severityCounts.Critical++
		case types.High:
			stats.severityCounts.High++
		case types.Medium:
			stats.severityCounts.Medium++
		case types.Low:
			stats.severityCounts.Low++
		}
		if ad := issue.GetAdditionalData(); ad != nil && ad.IsFixable() {
			stats.fixableCount++
		}
		if issue.GetIsIgnored() {
			stats.ignoredCount++
		}
	}
	return stats
}

func flattenIssues(issuesByFile snyk.IssuesByFile) []types.Issue {
	var all []types.Issue
	for _, issues := range issuesByFile {
		all = append(all, issues...)
	}
	return all
}

// buildFileNodes creates file-level nodes from issues grouped by file.
func (b *TreeBuilder) buildFileNodes(issuesByFile snyk.IssuesByFile, folderPath types.FilePath, p product.Product) []TreeNode {
	// Sort file paths alphabetically
	paths := make([]types.FilePath, 0, len(issuesByFile))
	for fp := range issuesByFile {
		paths = append(paths, fp)
	}
	sort.Slice(paths, func(i, j int) bool {
		return paths[i] < paths[j]
	})

	var fileNodes []TreeNode
	for _, path := range paths {
		issues := issuesByFile[path]
		issueNodes := b.buildIssueNodes(issues)
		uniqueCount := len(types.DeduplicateByFingerprint(issues))

		relPath := computeRelativePath(path, folderPath)
		desc := fileDescription(uniqueCount)

		// Only Open Source file nodes get a file icon (package manager SVG).
		// Non-OSS products (Code, IaC, Secrets) intentionally omit the icon.
		fileIcon := ""
		if p == product.ProductOpenSource && len(issues) > 0 {
			if fip, ok := issues[0].GetAdditionalData().(fileIconProvider); ok {
				fileIcon = fip.GetFileIcon(string(path))
			}
		}

		fileID := fmt.Sprintf("file:%s:%s", p, path)
		fileNode := NewTreeNode(NodeTypeFile, relPath,
			WithID(fileID),
			WithExpanded(b.resolveExpanded(fileID, NodeTypeFile)),
			WithFilePath(path),
			WithProduct(p),
			WithDescription(desc),
			WithIssueCount(uniqueCount),
			WithFileIconHTML(fileIcon),
			WithChildren(issueNodes),
		)
		fileNodes = append(fileNodes, fileNode)
	}

	return fileNodes
}

// fileDescription returns the issue-count text for a file node, e.g. "3 issues".
func fileDescription(count int) string {
	return fmt.Sprintf("%d %s", count, countWord(count))
}

// buildIssueNodes creates issue-level nodes, sorted by priority (severity + product score).
// Issues sharing the same fingerprint are grouped under a single parent issue node with
// NodeTypeLocation children (one per location). Single-occurrence findings use a flat layout.
// Labels are formatted per product type, matching IntelliJ's longTitle():
//   - OSS: "packageName@version: title"
//   - Single-location: "title [line,col]"
//   - Multi-location (grouped): "title" (range suffix moved to location child description)
func (b *TreeBuilder) buildIssueNodes(issues []types.Issue) []TreeNode {
	sorted := make([]types.Issue, len(issues))
	copy(sorted, issues)
	sortIssuesByPriority(sorted)

	// Group by fingerprint, preserving priority sort order.
	type fpGroup struct {
		fingerprint string
		issues      []types.Issue
	}
	var groups []fpGroup
	groupIdx := make(map[string]int)
	for _, issue := range sorted {
		fp := issue.GetFingerprint()
		if idx, exists := groupIdx[fp]; exists {
			groups[idx].issues = append(groups[idx].issues, issue)
		} else {
			groupIdx[fp] = len(groups)
			groups = append(groups, fpGroup{fingerprint: fp, issues: []types.Issue{issue}})
		}
	}

	var issueNodes []TreeNode
	for _, group := range groups {
		rep := group.issues[0]

		if len(group.issues) > 1 {
			// Multi-location: one issue node (title only) with location children.
			ad := rep.GetAdditionalData()
			fixable := false
			if ad != nil {
				fixable = ad.IsFixable()
			}

			var locationNodes []TreeNode
			for li, loc := range group.issues {
				locAD := loc.GetAdditionalData()
				locKey := ""
				if locAD != nil {
					locKey = locAD.GetKey()
				}
				locNode := NewTreeNode(NodeTypeLocation, locLabel(loc),
					WithID(fmt.Sprintf("location:%s:%d", group.fingerprint, li)),
					WithSeverity(loc.GetSeverity()),
					WithProduct(loc.GetProduct()),
					WithFilePath(loc.GetAffectedFilePath()),
					WithIssueRange(loc.GetRange()),
					WithIssueID(locKey),
					WithIsIgnored(loc.GetIsIgnored()),
					WithIsNew(loc.GetIsNew()),
				)
				locationNodes = append(locationNodes, locNode)
			}

			locCountDesc := fmt.Sprintf("%d locations", len(group.issues))
			issueGroupID := fmt.Sprintf("issue:%s", group.fingerprint)
			opts := []TreeNodeOption{
				WithID(issueGroupID),
				WithExpanded(b.resolveExpanded(issueGroupID, NodeTypeIssue)),
				WithSeverity(rep.GetSeverity()),
				WithProduct(rep.GetProduct()),
				WithFilePath(rep.GetAffectedFilePath()),
				WithIssueRange(rep.GetRange()),
				WithIssueID(group.fingerprint),
				WithDescription(locCountDesc),
				WithIsIgnored(rep.GetIsIgnored()),
				WithIsNew(rep.GetIsNew()),
				WithIsFixable(fixable),
				WithChildren(locationNodes),
			}
			issueNodes = append(issueNodes, NewTreeNode(NodeTypeIssue, issueTitleOnly(rep), opts...))
		} else {
			// Single location: existing flat layout.
			for _, issue := range group.issues {
				ad := issue.GetAdditionalData()
				issueKey := ""
				fixable := false
				if ad != nil {
					issueKey = ad.GetKey()
					fixable = ad.IsFixable()
				}
				opts := []TreeNodeOption{
					WithID(fmt.Sprintf("issue:%s", issue.GetID())),
					WithSeverity(issue.GetSeverity()),
					WithProduct(issue.GetProduct()),
					WithFilePath(issue.GetAffectedFilePath()),
					WithIssueRange(issue.GetRange()),
					WithIssueID(issueKey),
					WithIsIgnored(issue.GetIsIgnored()),
					WithIsNew(issue.GetIsNew()),
					WithIsFixable(fixable),
				}
				issueNodes = append(issueNodes, NewTreeNode(NodeTypeIssue, issueLabel(issue), opts...))
			}
		}
	}

	return issueNodes
}

// issueLabel formats the issue label with a [line,col] suffix for all product types.
// OSS issues additionally prefix with "packageName@version: ".
func issueLabel(issue types.Issue) string {
	title := issueTitleOnly(issue)
	r := issue.GetRange()
	return fmt.Sprintf("%s [%d, %d]", title, r.Start.Line+1, r.Start.Character+1)
}

// issueTitleOnly returns the issue title without a range suffix. Used as the label for
// multi-location secrets issue nodes where the range is shown on each location child instead.
func issueTitleOnly(issue types.Issue) string {
	ad := issue.GetAdditionalData()
	title := ""
	if ad != nil {
		title = ad.GetIssueNodePrefix() + ad.GetTitle()
	}
	if title == "" {
		title = issue.GetMessage()
	}
	return title
}

// locLabel returns the "[line,col]" range string used as the description of location nodes.
func locLabel(issue types.Issue) string {
	r := issue.GetRange()
	return fmt.Sprintf("Line %d, Column %d", r.Start.Line+1, r.Start.Character+1)
}

// resolveExpanded returns the expanded state for a node, using stored overrides or defaults.
// For file nodes in small trees (totalIssues <= maxAutoExpandIssues), the default is expanded
// unless the user has explicitly collapsed the node.
func (b *TreeBuilder) resolveExpanded(nodeID string, nodeType NodeType) bool {
	if b.expandState != nil {
		_, hasOverride := b.expandState.Get(nodeID)
		if hasOverride {
			return b.expandState.IsExpanded(nodeID, nodeType)
		}
	}
	// Auto-expand file nodes in small trees when no user override exists.
	// Decisions are collected in pendingAutoExpand and flushed after the tree
	// is fully built, keeping the build traversal read-only on ExpandState.
	if nodeType == NodeTypeFile && b.totalIssues > 0 && b.totalIssues <= maxAutoExpandIssues {
		if b.expandState != nil {
			if b.pendingAutoExpand == nil {
				b.pendingAutoExpand = make(map[string]bool)
			}
			b.pendingAutoExpand[nodeID] = true
		}
		return true
	}
	return defaultExpanded(nodeType)
}

func computeRelativePath(filePath types.FilePath, folderPath types.FilePath) string {
	rel, err := filepath.Rel(string(folderPath), string(filePath))
	if err != nil {
		return string(filePath)
	}
	// relPath is display-only (node label). Convert backslashes to forward
	// slashes so the JS middle-truncation logic (which scans for '/') works
	// correctly on Windows.
	return filepath.ToSlash(rel)
}

// sortIssuesByPriority sorts issues by descending priority (highest severity first,
// then by product-specific score, then by ID as tie-breaker), matching IntelliJ behavior.
func sortIssuesByPriority(issues []types.Issue) {
	sort.SliceStable(issues, func(i, j int) bool {
		pi := issuePriority(issues[i])
		pj := issuePriority(issues[j])
		if pi != pj {
			return pi > pj
		}
		return issues[i].GetID() < issues[j].GetID()
	})
}

// issuePriority computes a numeric priority matching IntelliJ's formula:
// severity * 1_000_000 + product-specific score.
func issuePriority(issue types.Issue) int {
	severityWeight := 0
	switch issue.GetSeverity() {
	case types.Critical:
		severityWeight = 4
	case types.High:
		severityWeight = 3
	case types.Medium:
		severityWeight = 2
	case types.Low:
		severityWeight = 1
	}

	score := 0
	if ad := issue.GetAdditionalData(); ad != nil {
		score = ad.GetScore()
	}

	return severityWeight*1_000_000 + score
}

// productScanErrorDescription matches scan_notifier SendError: errors listed in utils.ErrorConfig use
// TreeRootSuffix as the inline HTML tree description; unknown errors keep "- (scan failed)".
func productScanErrorDescription(scanError string) string {
	if meta, ok := utils.ErrorConfig[scanError]; ok && meta.TreeRootSuffix != "" {
		return "- " + meta.TreeRootSuffix
	}
	return "- (scan failed)"
}

// productSettingsDisabledTooltip is the hint for a scanner turned off via plugin
// settings. Used both when the product toggle is off (enabled == false) and when
// a scanner reports it's disabled for the folder — folder config is part of the
// plugin settings, so the user sees one consistent message either way.
func productSettingsDisabledTooltip(p product.Product) string {
	return fmt.Sprintf("%s scanning is disabled in Snyk plugin settings. Click the gear icon to re-enable it.", productDisplayName(p))
}

// productDisabledTooltip returns the hover hint for a scanner that produced a
// scan error. The wording is tailored to *why* it didn't run so the user knows
// whether they can act on it:
//   - org/entitlement disablement ("…not enabled for this organization") is not
//     self-serve, so the copy points the user at their org admin.
//   - folder-level disablement is a plugin-settings choice (folder config), so it
//     reuses the same settings message as the product toggle being off.
//   - anything else is a genuine scan failure the user can inspect via the
//     click-to-open error overlay.
func productDisabledTooltip(p product.Product, scanError string) string {
	switch scanError {
	case utils.ErrSnykCodeNotEnabled, utils.ErrSnykSecretsNotEnabled:
		return fmt.Sprintf("%s is disabled for your Snyk organization. Contact your org admin if you expected it to be available.", productDisplayName(p))
	case utils.ErrSnykCodeNotEnabledForFolder, utils.ErrSnykSecretsNotEnabledForFolder,
		utils.ErrSnykIacNotEnabledForFolder, utils.ErrSnykOssNotEnabledForFolder:
		return productSettingsDisabledTooltip(p)
	default:
		return fmt.Sprintf("%s couldn't be scanned. Click for details.", productDisplayName(p))
	}
}
