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

	"github.com/snyk/snyk-ls/domain/ide/treeview"
	"github.com/snyk/snyk-ls/internal/types"
)

// setNodeExpanded handles the snyk.setNodeExpanded command. It persists the
// expand/collapse state of a tree view node so that state survives re-renders.
type setNodeExpanded struct {
	command     types.CommandData
	expandState *treeview.ExpandState
}

func (cmd *setNodeExpanded) Command() types.CommandData {
	return cmd.command
}

func (cmd *setNodeExpanded) Execute(_ context.Context) (any, error) {
	args := cmd.command.Arguments
	if len(args) < 1 {
		return nil, fmt.Errorf("expected at least 1 argument, got %d", len(args))
	}

	// Batch format: args[0] = [[nodeID, expanded], ...] — used by expand/collapse all
	if batch, ok := args[0].([]any); ok {
		for _, entry := range batch {
			pair, pairOk := entry.([]any)
			if !pairOk || len(pair) < 2 {
				continue
			}
			nodeID, _ := pair[0].(string)
			expanded, _ := pair[1].(bool)
			if nodeID != "" {
				cmd.expandState.Set(nodeID, expanded)
			}
		}
		return nil, nil
	}

	// Single format: args[0] = nodeID, args[1] = expanded
	if len(args) < 2 {
		return nil, fmt.Errorf("expected 2 arguments [nodeID, expanded], got %d", len(args))
	}
	nodeID, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("nodeID must be a string")
	}
	expanded, ok := args[1].(bool)
	if !ok {
		return nil, fmt.Errorf("expanded must be a bool")
	}
	cmd.expandState.Set(nodeID, expanded)
	return nil, nil
}
