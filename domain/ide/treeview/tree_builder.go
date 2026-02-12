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
type TreeBuilder struct{}

// NewTreeBuilder creates a new TreeBuilder.
func NewTreeBuilder() *TreeBuilder {
	return &TreeBuilder{}
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

	if multiRoot {
		for _, fd := range folders {
			folderNode := NewTreeNode(NodeTypeFolder, fd.FolderName,
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
		pIssues, exists := issuesByProduct[p]
		if !exists || len(pIssues) == 0 {
			continue
		}

		fileNodes := b.buildFileNodes(pIssues, fd.FolderPath)
		totalIssues := countTotalIssues(pIssues)

		productNode := NewTreeNode(NodeTypeProduct, string(p),
			WithProduct(p),
			WithDescription(fmt.Sprintf("%d issue(s)", totalIssues)),
			WithChildren(fileNodes),
		)
		productNodes = append(productNodes, productNode)
	}

	return productNodes
}

// buildFileNodes creates file-level nodes from issues grouped by file.
func (b *TreeBuilder) buildFileNodes(issuesByFile snyk.IssuesByFile, folderPath types.FilePath) []TreeNode {
	// Sort file paths alphabetically
	paths := make([]types.FilePath, 0, len(issuesByFile))
	for p := range issuesByFile {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool {
		return paths[i] < paths[j]
	})

	var fileNodes []TreeNode
	for _, path := range paths {
		issues := issuesByFile[path]
		issueNodes := b.buildIssueNodes(issues)

		// Compute relative path for the label
		relPath := computeRelativePath(path, folderPath)

		fileNode := NewTreeNode(NodeTypeFile, relPath,
			WithFilePath(path),
			WithDescription(fmt.Sprintf("%d issue(s)", len(issues))),
			WithChildren(issueNodes),
		)
		fileNodes = append(fileNodes, fileNode)
	}

	return fileNodes
}

// buildIssueNodes creates issue-level leaf nodes, sorted by severity (critical first).
func (b *TreeBuilder) buildIssueNodes(issues []types.Issue) []TreeNode {
	// Sort by severity (Critical=0 is lowest value → sort ascending)
	sorted := make([]types.Issue, len(issues))
	copy(sorted, issues)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].GetSeverity() < sorted[j].GetSeverity()
	})

	var issueNodes []TreeNode
	for _, issue := range sorted {
		title := issue.GetAdditionalData().GetTitle()
		if title == "" {
			title = issue.GetMessage()
		}

		opts := []TreeNodeOption{
			WithSeverity(issue.GetSeverity()),
			WithProduct(issue.GetProduct()),
			WithFilePath(issue.GetAffectedFilePath()),
			WithIssueRange(issue.GetRange()),
			WithIssueID(issue.GetID()),
			WithIsIgnored(issue.GetIsIgnored()),
			WithIsNew(issue.GetIsNew()),
			WithIsFixable(issue.GetAdditionalData().IsFixable()),
		}

		issueNodes = append(issueNodes, NewTreeNode(NodeTypeIssue, title, opts...))
	}

	return issueNodes
}

func countTotalIssues(issuesByFile snyk.IssuesByFile) int {
	total := 0
	for _, issues := range issuesByFile {
		total += len(issues)
	}
	return total
}

func computeRelativePath(filePath types.FilePath, folderPath types.FilePath) string {
	rel, err := filepath.Rel(string(folderPath), string(filePath))
	if err != nil {
		return string(filePath)
	}
	return rel
}
