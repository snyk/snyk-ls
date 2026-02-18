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

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

// TreeViewEmitter builds and sends the tree view HTML to the IDE via notification.
type TreeViewEmitter struct {
	notifier notification.Notifier
	c        *config.Config
	builder  *TreeBuilder
	renderer *TreeHtmlRenderer
}

// NewTreeViewEmitter creates a new TreeViewEmitter.
func NewTreeViewEmitter(c *config.Config, n notification.Notifier) (*TreeViewEmitter, error) {
	renderer, err := NewTreeHtmlRenderer(c)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize TreeHtmlRenderer: %w", err)
	}

	return &TreeViewEmitter{
		notifier: n,
		c:        c,
		builder:  NewTreeBuilder(),
		renderer: renderer,
	}, nil
}

// Emit builds the tree from folder data and sends the rendered HTML as a notification.
// Scan states are inferred from the folder data: each enabled product is marked as scan-complete.
func (e *TreeViewEmitter) Emit(folderData []FolderData) {
	e.builder.SetProductScanStates(deriveCompletedScanStates(folderData))
	data := e.builder.BuildTreeFromFolderData(folderData)
	html := e.renderer.RenderTreeView(data)
	e.notifier.Send(types.TreeView{TreeViewHtml: html, TotalIssues: data.TotalIssues})
}

func deriveCompletedScanStates(folders []FolderData) map[types.FilePath]map[product.Product]bool {
	states := make(map[types.FilePath]map[product.Product]bool)
	for _, fd := range folders {
		m := make(map[product.Product]bool)
		for issueType := range fd.SupportedIssueTypes {
			p := issueType.ToProduct()
			if p != product.ProductUnknown {
				m[p] = false // false = completed, not in progress
			}
		}
		states[fd.FolderPath] = m
	}
	return states
}

// EmitFromWorkspace builds the tree directly from the workspace and sends it.
func (e *TreeViewEmitter) EmitFromWorkspace() {
	ws := e.c.Workspace()
	if ws == nil {
		return
	}
	data := e.builder.BuildTree(ws)
	html := e.renderer.RenderTreeView(data)
	e.notifier.Send(types.TreeView{TreeViewHtml: html, TotalIssues: data.TotalIssues})
}
