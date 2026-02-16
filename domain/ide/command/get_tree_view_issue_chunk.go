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
	"encoding/json"
	"fmt"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/treeview"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

type getTreeViewIssueChunk struct {
	command types.CommandData
	c       *config.Config
}

func (cmd *getTreeViewIssueChunk) Command() types.CommandData {
	return cmd.command
}

func (cmd *getTreeViewIssueChunk) Execute(_ context.Context) (any, error) {
	params, err := parseGetTreeViewIssueChunkParams(cmd.command.Arguments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse getTreeViewIssueChunk params: %w", err)
	}

	ws := cmd.c.Workspace()
	if ws == nil {
		return types.GetTreeViewIssueChunkResult{
			IssueNodesHtml:  "",
			TotalFileIssues: 0,
			HasMore:         false,
			NextStart:       params.Range.Start,
		}, nil
	}

	renderer, err := treeview.NewTreeHtmlRenderer(cmd.c)
	if err != nil {
		return nil, fmt.Errorf("failed to create tree view renderer: %w", err)
	}

	builder := treeview.NewTreeBuilder()
	issueNodes, total := builder.BuildIssueChunkForFile(
		ws,
		types.FilePath(params.FilePath),
		product.Product(params.Product),
		params.Range,
	)

	start := params.Range.Start
	if start < 0 {
		start = 0
	}
	end := params.Range.End
	if end < start {
		end = start
	}
	if end > total {
		end = total
	}
	hasMore := end < total

	return types.GetTreeViewIssueChunkResult{
		IssueNodesHtml:  renderer.RenderIssueChunk(issueNodes, hasMore),
		TotalFileIssues: total,
		HasMore:         hasMore,
		NextStart:       end,
	}, nil
}

func parseGetTreeViewIssueChunkParams(arguments []any) (types.GetTreeViewIssueChunkParams, error) {
	if len(arguments) == 0 {
		return types.GetTreeViewIssueChunkParams{}, fmt.Errorf("missing getTreeViewIssueChunk arguments")
	}

	raw, err := json.Marshal(arguments[0])
	if err != nil {
		return types.GetTreeViewIssueChunkParams{}, fmt.Errorf("failed to marshal getTreeViewIssueChunk arguments: %w", err)
	}

	var params types.GetTreeViewIssueChunkParams
	if err := json.Unmarshal(raw, &params); err != nil {
		return types.GetTreeViewIssueChunkParams{}, fmt.Errorf("failed to unmarshal getTreeViewIssueChunk arguments: %w", err)
	}

	if params.FilePath == "" {
		return types.GetTreeViewIssueChunkParams{}, fmt.Errorf("filePath is required")
	}
	if params.Product == "" {
		return types.GetTreeViewIssueChunkParams{}, fmt.Errorf("product is required")
	}

	return params, nil
}
