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
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)

// TreeScanStateEmitter adapts the ScanStateChangeEmitter interface to emit tree view HTML.
// It is registered alongside the summary emitter in the composite emitter.
type TreeScanStateEmitter struct {
	notifier notification.Notifier
	c        *config.Config
	builder  *TreeBuilder
	renderer *TreeHtmlRenderer
}

// NewTreeScanStateEmitter creates a new TreeScanStateEmitter.
func NewTreeScanStateEmitter(c *config.Config, n notification.Notifier) (*TreeScanStateEmitter, error) {
	renderer, err := NewTreeHtmlRenderer(c)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize TreeHtmlRenderer: %w", err)
	}

	return &TreeScanStateEmitter{
		notifier: n,
		c:        c,
		builder:  NewTreeBuilder(),
		renderer: renderer,
	}, nil
}

// Emit implements ScanStateChangeEmitter. It builds the tree from the workspace
// and sends it as a $/snyk.treeView notification.
func (e *TreeScanStateEmitter) Emit(state scanstates.StateSnapshot) {
	scanInProgress := state.AnyScanInProgressWorkingDirectory || state.AnyScanInProgressReference

	ws := e.c.Workspace()
	var data TreeViewData
	if ws != nil {
		data = e.buildTreeFromWorkspace(ws)
	}
	data.ScanInProgress = scanInProgress

	html := e.renderer.RenderTreeView(data)
	e.notifier.Send(types.TreeView{TreeViewHtml: html, TotalIssues: data.TotalIssues})
}

func (e *TreeScanStateEmitter) buildTreeFromWorkspace(ws types.Workspace) TreeViewData {
	folders := ws.Folders()
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

	return e.builder.BuildTreeFromFolderData(folderDataList)
}
