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
}

// TreeBuilder constructs a TreeViewData hierarchy from workspace folder data.
type TreeBuilder struct {
	expandState *ExpandState
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

		folderDataList = append(folderDataList, FolderData{
			FolderPath:          f.Path(),
			FolderName:          f.Name(),
			SupportedIssueTypes: supportedTypes,
			AllIssues:           allIssues,
			FilteredIssues:      filtered,
		})
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

	if multiRoot {
		for _, fd := range folders {
			folderID := fmt.Sprintf("folder:%s", fd.FolderPath)
			folderNode := NewTreeNode(NodeTypeFolder, fd.FolderName,
				WithID(folderID),
				WithExpanded(b.resolveExpanded(folderID, NodeTypeFolder)),
				WithFilePath(fd.FolderPath),
				WithChildren(b.buildProductNodes(fd)),
			)
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

	// Define product ordering
	productOrder := []product.Product{
		product.ProductCode,
		product.ProductOpenSource,
		product.ProductInfrastructureAsCode,
	}

	var productNodes []TreeNode
	for _, p := range productOrder {
		pIssues := issuesByProduct[p]
		allIssues := flattenIssues(pIssues)
		totalIssues := len(allIssues)

		// Compute severity breakdown
		counts := computeSeverityCounts(allIssues)
		fixableCount := computeFixableCount(allIssues)

		// Build description with severity breakdown (matching IntelliJ)
		desc := productDescription(p, totalIssues, counts)

		// Build children: info nodes first, then file nodes
		productKey := fmt.Sprintf("product:%s:%s", fd.FolderPath, p)
		var children []TreeNode
		children = append(children, b.buildInfoNodes(productKey, totalIssues, fixableCount)...)

		if totalIssues > 0 {
			children = append(children, b.buildFileNodes(pIssues, fd.FolderPath, p)...)
		}

		productID := fmt.Sprintf("product:%s:%s", fd.FolderPath, p)
		productNode := NewTreeNode(NodeTypeProduct, string(p),
			WithID(productID),
			WithExpanded(b.resolveExpanded(productID, NodeTypeProduct)),
			WithProduct(p),
			WithDescription(desc),
			WithSeverityCounts(counts),
			WithFixableCount(fixableCount),
			WithIssueCount(totalIssues),
			WithChildren(children),
		)
		productNodes = append(productNodes, productNode)
	}

	return productNodes
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
func productDescription(p product.Product, totalIssues int, counts *SeverityCounts) string {
	if totalIssues == 0 {
		return "No issues found"
	}

	countWord := productCountWord(p, totalIssues)
	return fmt.Sprintf("%d %s: %d critical, %d high, %d medium, %d low",
		totalIssues, countWord,
		counts.Critical, counts.High, counts.Medium, counts.Low)
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

		opts := []TreeNodeOption{
			WithID(fmt.Sprintf("issue:%s", issue.GetID())),
			WithSeverity(issue.GetSeverity()),
			WithProduct(issue.GetProduct()),
			WithFilePath(issue.GetAffectedFilePath()),
			WithIssueRange(issue.GetRange()),
			WithIssueID(issue.GetID()),
			WithIsIgnored(issue.GetIsIgnored()),
			WithIsNew(issue.GetIsNew()),
			WithIsFixable(issue.GetAdditionalData().IsFixable()),
		}

		issueNodes = append(issueNodes, NewTreeNode(NodeTypeIssue, label, opts...))
	}

	return issueNodes
}

// issueLabel formats the issue label per product type, matching IntelliJ's longTitle().
func issueLabel(issue types.Issue) string {
	ad := issue.GetAdditionalData()
	title := ad.GetTitle()
	if title == "" {
		title = issue.GetMessage()
	}

	p := issue.GetProduct()
	switch p {
	case product.ProductOpenSource:
		pkgName := ad.GetPackageName()
		version := ad.GetVersion()
		if pkgName != "" && version != "" {
			return fmt.Sprintf("%s@%s: %s", pkgName, version, title)
		}
		if pkgName != "" {
			return fmt.Sprintf("%s: %s", pkgName, title)
		}
		return title
	default:
		// Code and IaC: "title [line,col]"
		r := issue.GetRange()
		return fmt.Sprintf("%s [%d,%d]", title, r.Start.Line+1, r.Start.Character)
	}
}

// resolveExpanded returns the expanded state for a node, using stored overrides or defaults.
func (b *TreeBuilder) resolveExpanded(nodeID string, nodeType NodeType) bool {
	if b.expandState != nil {
		return b.expandState.IsExpanded(nodeID, nodeType)
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

// BuildIssueChunkForFile returns a paginated slice of issue nodes for a specific file and product,
// plus the total count of matching issues. Issues are sorted by priority (severity + product score).
func (b *TreeBuilder) BuildIssueChunkForFile(
	workspace types.Workspace,
	filePath types.FilePath,
	p product.Product,
	r types.TreeViewRange,
) ([]TreeNode, int) {
	folders := workspace.Folders()
	if len(folders) == 0 {
		return nil, 0
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
		folderDataList = append(folderDataList, FolderData{
			FolderPath:          f.Path(),
			FolderName:          f.Name(),
			SupportedIssueTypes: supportedTypes,
			AllIssues:           allIssues,
			FilteredIssues:      filtered,
		})
	}

	return b.BuildIssueChunkForFileFromFolderData(folderDataList, filePath, p, r)
}

// BuildIssueChunkForFileFromFolderData returns paginated issue nodes for a file+product from pre-fetched data.
func (b *TreeBuilder) BuildIssueChunkForFileFromFolderData(
	folders []FolderData,
	filePath types.FilePath,
	p product.Product,
	r types.TreeViewRange,
) ([]TreeNode, int) {
	if len(folders) == 0 {
		return nil, 0
	}

	var matchingIssues []types.Issue
	for _, fd := range folders {
		for path, issues := range fd.FilteredIssues {
			if path != filePath {
				continue
			}
			for _, issue := range issues {
				if issue.GetProduct() == p {
					matchingIssues = append(matchingIssues, issue)
				}
			}
		}
	}

	sortIssuesByPriority(matchingIssues)
	total := len(matchingIssues)

	start := r.Start
	if start < 0 {
		start = 0
	}
	end := r.End
	if end > total {
		end = total
	}
	if start > total {
		start = total
	}

	chunk := matchingIssues[start:end]
	nodes := b.buildIssueNodes(chunk)
	return nodes, total
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
