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

package command

import (
	"context"
	"fmt"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/treeview"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/internal/types"
)

type getTreeViewCommand struct {
	command       types.CommandData
	c             *config.Config
	scanStateFunc func() scanstates.StateSnapshot
}

func (cmd *getTreeViewCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *getTreeViewCommand) Execute(_ context.Context) (any, error) {
	renderer, err := treeview.NewTreeHtmlRenderer(cmd.c)
	if err != nil {
		return nil, fmt.Errorf("failed to create tree view renderer: %w", err)
	}

	builder := treeview.NewTreeBuilder(treeview.GlobalExpandState())
	if cmd.scanStateFunc != nil {
		state := cmd.scanStateFunc()
		builder.SetProductScanStates(state.ProductScanStates)
		builder.SetProductScanErrors(state.ProductScanErrors)
	}

	var data treeview.TreeViewData
	ws := cmd.c.Workspace()
	if ws != nil {
		data = builder.BuildTree(ws)
	}
	data.FilterState = treeview.TreeViewFilterState{
		SeverityFilter:   cmd.c.FilterSeverity(),
		IssueViewOptions: cmd.c.IssueViewOptions(),
	}

	return renderer.RenderTreeView(data), nil
}
