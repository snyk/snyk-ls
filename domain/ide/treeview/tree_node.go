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

// Package treeview provides types and logic for building a server-driven HTML tree view
// of Snyk scan results that is rendered as a web view in IDEs.
package treeview

import (
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

// NodeType represents the type of a tree view node.
type NodeType string

const (
	NodeTypeFolder  NodeType = "folder"
	NodeTypeProduct NodeType = "product"
	NodeTypeFile    NodeType = "file"
	NodeTypeIssue   NodeType = "issue"
	NodeTypeInfo    NodeType = "info"
)

// SeverityCounts holds per-severity issue counts for product and file nodes.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// TreeNode represents a single node in the tree view hierarchy.
type TreeNode struct {
	ID             string          `json:"id"`
	Type           NodeType        `json:"type"`
	Label          string          `json:"label"`
	Description    string          `json:"description,omitempty"`
	Severity       types.Severity  `json:"severity,omitempty"`
	Product        product.Product `json:"product,omitempty"`
	FilePath       types.FilePath  `json:"filePath,omitempty"`
	IssueRange     types.Range     `json:"issueRange,omitempty"`
	IssueID        string          `json:"issueId,omitempty"`
	IsIgnored      bool            `json:"isIgnored,omitempty"`
	IsNew          bool            `json:"isNew,omitempty"`
	IsFixable      bool            `json:"isFixable,omitempty"`
	SeverityCounts *SeverityCounts `json:"severityCounts,omitempty"`
	FixableCount   int             `json:"fixableCount,omitempty"`
	IssueCount     int             `json:"issueCount,omitempty"`
	Expanded       bool            `json:"expanded,omitempty"`
	Enabled        *bool           `json:"enabled,omitempty"`
	Children       []TreeNode      `json:"children,omitempty"`
}

// TreeViewFilterState captures the current filter settings for the tree view.
type TreeViewFilterState struct {
	SeverityFilter   types.SeverityFilter   `json:"severityFilter"`
	IssueViewOptions types.IssueViewOptions `json:"issueViewOptions"`
}

// DefaultTreeViewFilterState returns filter state with all filters enabled.
func DefaultTreeViewFilterState() TreeViewFilterState {
	return TreeViewFilterState{
		SeverityFilter:   types.DefaultSeverityFilter(),
		IssueViewOptions: types.DefaultIssueViewOptions(),
	}
}

// TreeViewData is the top-level data structure passed to the HTML template.
type TreeViewData struct {
	Nodes          []TreeNode          `json:"nodes"`
	FilterState    TreeViewFilterState `json:"filterState"`
	TotalIssues    int                 `json:"totalIssues"`
	ScanInProgress bool                `json:"scanInProgress"`
	MultiRoot      bool                `json:"multiRoot"`
}

// TreeNodeOption is a functional option for configuring a TreeNode.
type TreeNodeOption func(*TreeNode)

// NewTreeNode creates a new TreeNode with the given type, label, and options.
// The ID is empty by default; callers should set it via WithID for deterministic
// identification across re-renders (required for expand/collapse state persistence).
func NewTreeNode(nodeType NodeType, label string, opts ...TreeNodeOption) TreeNode {
	node := TreeNode{
		Type:  nodeType,
		Label: label,
	}
	for _, opt := range opts {
		opt(&node)
	}
	return node
}

func WithID(id string) TreeNodeOption {
	return func(n *TreeNode) { n.ID = id }
}

func WithDescription(desc string) TreeNodeOption {
	return func(n *TreeNode) { n.Description = desc }
}

func WithSeverity(s types.Severity) TreeNodeOption {
	return func(n *TreeNode) { n.Severity = s }
}

func WithProduct(p product.Product) TreeNodeOption {
	return func(n *TreeNode) { n.Product = p }
}

func WithFilePath(fp types.FilePath) TreeNodeOption {
	return func(n *TreeNode) { n.FilePath = fp }
}

func WithIssueRange(r types.Range) TreeNodeOption {
	return func(n *TreeNode) { n.IssueRange = r }
}

func WithIssueID(id string) TreeNodeOption {
	return func(n *TreeNode) { n.IssueID = id }
}

func WithIsIgnored(ignored bool) TreeNodeOption {
	return func(n *TreeNode) { n.IsIgnored = ignored }
}

func WithIsNew(isNew bool) TreeNodeOption {
	return func(n *TreeNode) { n.IsNew = isNew }
}

func WithIsFixable(fixable bool) TreeNodeOption {
	return func(n *TreeNode) { n.IsFixable = fixable }
}

func WithSeverityCounts(counts *SeverityCounts) TreeNodeOption {
	return func(n *TreeNode) { n.SeverityCounts = counts }
}

func WithFixableCount(count int) TreeNodeOption {
	return func(n *TreeNode) { n.FixableCount = count }
}

func WithIssueCount(count int) TreeNodeOption {
	return func(n *TreeNode) { n.IssueCount = count }
}

func WithExpanded(expanded bool) TreeNodeOption {
	return func(n *TreeNode) { n.Expanded = expanded }
}

func WithEnabled(enabled *bool) TreeNodeOption {
	return func(n *TreeNode) { n.Enabled = enabled }
}

func WithChildren(children []TreeNode) TreeNodeOption {
	return func(n *TreeNode) { n.Children = children }
}
