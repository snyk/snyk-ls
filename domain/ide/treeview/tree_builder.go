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
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

// FolderData contains pre-fetched data for a workspace folder, decoupling the builder
// from the folder interface and making it testable without requiring full folder mocks.
type FolderData struct {
	FolderPath          types.FilePath
	FolderName          string
	SupportedIssueTypes map[product.FilterableIssueType]bool
	AllIssues           snyk.IssuesByFile
	FilteredIssues      snyk.IssuesByFile
	DeltaEnabled        bool
	BaseBranch          string
	LocalBranches       []string
	ReferenceFolderPath string
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
		supportedTypes := f.DisplayableIssueTypes()
		allIssues := fip.Issues()
		filtered := fip.FilterIssues(allIssues, supportedTypes)

		fd := FolderData{
			FolderPath:          f.Path(),
			FolderName:          f.Name(),
			SupportedIssueTypes: supportedTypes,
			AllIssues:           allIssues,
			FilteredIssues:      filtered,
			DeltaEnabled:        f.IsDeltaFindingsEnabled(),
		}
		if fd.DeltaEnabled {
			if cfg := f.FolderConfigReadOnly(); cfg != nil {
				fd.BaseBranch = cfg.GetBaseBranch()
				fd.LocalBranches = cfg.GetLocalBranches()
				fd.ReferenceFolderPath = string(cfg.GetReferenceFolderPath())
			}
		}
		folderDataList = append(folderDataList, fd)
	}

	return b.BuildTreeFromFolderData(folderDataList)
}

// BuildTreeFromFolderData builds the tree from pre-fetched folder data.
func (b *TreeBuilder) BuildTreeFromFolderData(folders []FolderData) TreeViewData {
	multiRoot := len(folders) > 1
	data := TreeViewData{
		MultiRoot: multiRoot,
	}

	totalIssues := 0
	for _, fd := range folders {
		for _, issues := range fd.FilteredIssues {
			totalIssues += len(issues)
		}
	}
	data.TotalIssues = totalIssues
	b.totalIssues = totalIssues

	// Show folder nodes when multi-root OR single-folder with delta enabled.
	// In IntelliJ native tree, the folder node is hidden in single-folder mode unless
	// delta is enabled (the folder node is needed for reference folder selection).
	showFolderNodes := multiRoot || (len(folders) == 1 && folders[0].DeltaEnabled)

	if showFolderNodes {
		for _, fd := range folders {
			folderID := fmt.Sprintf("folder:%s", fd.FolderPath)
			opts := []TreeNodeOption{
				WithID(folderID),
				WithExpanded(b.resolveExpanded(folderID, NodeTypeFolder)),
				WithFilePath(fd.FolderPath),
				WithChildren(b.buildProductNodes(fd)),
			}
			if fd.DeltaEnabled {
				opts = append(opts, WithDeltaEnabled(true))
				if len(fd.LocalBranches) > 0 {
					opts = append(opts, WithLocalBranches(fd.LocalBranches))
				}
				// Only one of BaseBranch or ReferenceFolderPath is set on the node.
				// BaseBranch takes precedence when both are present in FolderData.
				if fd.BaseBranch != "" {
					opts = append(opts, WithDescription(fmt.Sprintf("base: %s", fd.BaseBranch)))
					opts = append(opts, WithBaseBranch(fd.BaseBranch))
				} else if fd.ReferenceFolderPath != "" {
					opts = append(opts, WithDescription(fmt.Sprintf("ref: %s", fd.ReferenceFolderPath)))
					opts = append(opts, WithReferenceFolderPath(fd.ReferenceFolderPath))
				}
			}
			folderNode := NewTreeNode(NodeTypeFolder, fd.FolderName, opts...)
			data.Nodes = append(data.Nodes, folderNode)
		}
	} else if len(folders) == 1 {
		data.Nodes = b.buildProductNodes(folders[0])
	}

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

	// Product ordering matches native IntelliJ tree: Open Source → Code Security → Infrastructure As Code
	productOrder := []product.Product{
		product.ProductOpenSource,
		product.ProductCode,
		product.ProductInfrastructureAsCode,
	}

	var productNodes []TreeNode
	for _, p := range productOrder {
		pIssues := issuesByProduct[p]
		allIssues := flattenIssues(pIssues)
		totalIssues := len(allIssues)

		// Determine whether this product is enabled via SupportedIssueTypes
		enabled := isProductEnabled(p, fd.SupportedIssueTypes)

		// Compute severity breakdown
		counts := computeSeverityCounts(allIssues)
		fixableCount := computeFixableCount(allIssues)

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
				desc = "- " + productDescription(p, totalIssues, counts) + " (scanning...)"
			}
		} else if scanError != "" {
			desc = "- (scan failed)"
		} else if scanRegistered {
			desc = "- " + productDescription(p, totalIssues, counts)
		}
		// else: no scan registered yet → empty description (initial state)

		// Build children: info nodes first, then file nodes (only for enabled products with completed scans)
		productKey := fmt.Sprintf("product:%s:%s", fd.FolderPath, p)
		var children []TreeNode
		if enabled && scanRegistered && !scanning && scanError == "" {
			children = append(children, b.buildInfoNodes(productKey, totalIssues, fixableCount)...)

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
			WithSeverityCounts(counts),
			WithFixableCount(fixableCount),
			WithIssueCount(totalIssues),
			WithEnabled(&enabled),
			WithErrorMessage(scanError),
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

// buildInfoNodes creates info child nodes for a product, matching IntelliJ addInfoTreeNodes().
func (b *TreeBuilder) buildInfoNodes(parentKey string, totalIssues int, fixableCount int) []TreeNode {
	var infoNodes []TreeNode

	if totalIssues == 0 {
		infoNodes = append(infoNodes, NewTreeNode(NodeTypeInfo, "✅ Congrats! No issues found!",
			WithID(fmt.Sprintf("info:%s:congrats", parentKey))))
	} else {
		// Issue count line
		issueWord := "issues"
		if totalIssues == 1 {
			issueWord = "issue"
		}
		infoNodes = append(infoNodes, NewTreeNode(NodeTypeInfo, fmt.Sprintf("✋ %d %s", totalIssues, issueWord),
			WithID(fmt.Sprintf("info:%s:count", parentKey))))

		// Fixable line
		if fixableCount > 0 {
			fixWord := "issues are"
			if fixableCount == 1 {
				fixWord = "issue is"
			}
			infoNodes = append(infoNodes, NewTreeNode(NodeTypeInfo,
				fmt.Sprintf("⚡ %d %s fixable automatically.", fixableCount, fixWord),
				WithID(fmt.Sprintf("info:%s:fixable", parentKey))))
		} else {
			infoNodes = append(infoNodes, NewTreeNode(NodeTypeInfo, "There are no issues automatically fixable.",
				WithID(fmt.Sprintf("info:%s:fixable", parentKey))))
		}
	}

	return infoNodes
}

// productDescription builds the severity breakdown description for a product node.
// Only non-zero severity counts are included.
func productDescription(p product.Product, totalIssues int, counts *SeverityCounts) string {
	if totalIssues == 0 {
		return "No issues found"
	}

	countWord := productCountWord(p, totalIssues)
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
		return fmt.Sprintf("%d %s", totalIssues, countWord)
	}
	return fmt.Sprintf("%d %s: %s", totalIssues, countWord, strings.Join(parts, ", "))
}

// productCountWord returns "vulnerabilities"/"vulnerability" for OSS, "issues"/"issue" for Code/IaC.
func productCountWord(p product.Product, count int) string {
	if p == product.ProductOpenSource {
		if count == 1 {
			return "unique vulnerability"
		}
		return "unique vulnerabilities"
	}
	if count == 1 {
		return "issue"
	}
	return "issues"
}

func computeSeverityCounts(issues []types.Issue) *SeverityCounts {
	counts := &SeverityCounts{}
	for _, issue := range issues {
		switch issue.GetSeverity() {
		case types.Critical:
			counts.Critical++
		case types.High:
			counts.High++
		case types.Medium:
			counts.Medium++
		case types.Low:
			counts.Low++
		}
	}
	return counts
}

func computeFixableCount(issues []types.Issue) int {
	count := 0
	for _, issue := range issues {
		if ad := issue.GetAdditionalData(); ad != nil && ad.IsFixable() {
			count++
		}
	}
	return count
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

		relPath := computeRelativePath(path, folderPath)
		desc := fileDescription(p, len(issues))

		fileID := fmt.Sprintf("file:%s:%s", p, path)
		fileNode := NewTreeNode(NodeTypeFile, relPath,
			WithID(fileID),
			WithExpanded(b.resolveExpanded(fileID, NodeTypeFile)),
			WithFilePath(path),
			WithProduct(p),
			WithDescription(desc),
			WithIssueCount(len(issues)),
			WithChildren(issueNodes),
		)
		fileNodes = append(fileNodes, fileNode)
	}

	return fileNodes
}

// fileDescription returns product-aware text: "N vulnerabilities" for OSS, "N issues" for Code/IaC.
func fileDescription(p product.Product, count int) string {
	word := productCountWord(p, count)
	return fmt.Sprintf("%d %s", count, word)
}

// buildIssueNodes creates issue-level leaf nodes, sorted by priority (severity + product score).
// Labels are formatted per product type, matching IntelliJ's longTitle():
//   - OSS: "packageName@version: title"
//   - Code/IaC: "title [line,col]"
func (b *TreeBuilder) buildIssueNodes(issues []types.Issue) []TreeNode {
	sorted := make([]types.Issue, len(issues))
	copy(sorted, issues)
	sortIssuesByPriority(sorted)

	var issueNodes []TreeNode
	for _, issue := range sorted {
		label := issueLabel(issue)

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

		issueNodes = append(issueNodes, NewTreeNode(NodeTypeIssue, label, opts...))
	}

	return issueNodes
}

// issueLabel formats the issue label with a [line,col] suffix for all product types.
// OSS issues additionally prefix with "packageName@version: ".
func issueLabel(issue types.Issue) string {
	ad := issue.GetAdditionalData()

	title := ""
	if ad != nil {
		title = ad.GetTitle()
	}
	if title == "" {
		title = issue.GetMessage()
	}

	if issue.GetProduct() == product.ProductOpenSource && ad != nil {
		pkgName := ad.GetPackageName()
		version := ad.GetVersion()
		if pkgName != "" && version != "" {
			title = fmt.Sprintf("%s@%s: %s", pkgName, version, title)
		} else if pkgName != "" {
			title = fmt.Sprintf("%s: %s", pkgName, title)
		}
	}

	r := issue.GetRange()
	return fmt.Sprintf("%s [%d,%d]", title, r.Start.Line+1, r.Start.Character)
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
	// Not persisted: auto-expand is re-evaluated each render based on current tree size.
	if nodeType == NodeTypeFile && b.totalIssues > 0 && b.totalIssues <= maxAutoExpandIssues {
		return true
	}
	return defaultExpanded(nodeType)
}

func computeRelativePath(filePath types.FilePath, folderPath types.FilePath) string {
	rel, err := filepath.Rel(string(folderPath), string(filePath))
	if err != nil {
		return string(filePath)
	}
	return rel
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
