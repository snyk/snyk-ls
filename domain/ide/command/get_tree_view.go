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

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/treeview"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/internal/types"
)

type getTreeViewCommand struct {
	command       types.CommandData
	engine        workflow.Engine
	scanStateFunc func() scanstates.StateSnapshot
}

func (cmd *getTreeViewCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *getTreeViewCommand) Execute(_ context.Context) (any, error) {
	renderer, err := treeview.NewTreeHtmlRenderer(cmd.engine.GetLogger())
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
	conf := cmd.engine.GetConfiguration()
	ws := config.GetWorkspace(conf)
	if ws != nil {
		data = builder.BuildTree(ws)
	}
	// Use the shared aggregation so this on-demand render matches the scan
	// emitter's toolbar — including the filter popover gating and the cross-folder
	// "mixed" state. Building FilterState from global config alone would leave the
	// popover hidden and mixed flags unset on this path.
	data.FilterState = treeview.BuildFilterState(conf, ws)

	return renderer.RenderTreeView(data), nil
}
